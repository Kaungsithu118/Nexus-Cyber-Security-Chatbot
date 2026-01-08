# app.py — Nexus Bot backend (original structure + consent + threat simulation + export)
# Notes:
#   - /api/consent preserves your cookie/DB consent behavior
#   - /scan_url and /upload respect consent and return JSON
#   - Threat Simulation API:
#       POST /api/simulate        => create scenario
#       POST /api/simulate/grade  => grade user response
#       POST /api/threat/simulate => UI shim (returns {result:{level,risk,hits}, tips})
#   - Export:
#       GET /api/chat/export?chat_id=...&format=txt|csv|pdf

from flask import Flask, render_template, request, jsonify, send_from_directory, Response, make_response, send_file
import os, re, time, base64, hashlib, zipfile, wave, json, csv, io, textwrap, secrets, uuid, datetime, random
from pathlib import Path
from typing import Tuple, Dict, Any, Optional, List
from urllib.parse import urlparse
import math

# --- Google ID Token verification imports (add-on) ---
try:
    from google.oauth2 import id_token as google_id_token
    from google.auth.transport import requests as google_requests
except Exception:
    google_id_token = None
    google_requests = None
try:
    import requests as pyrequests
except Exception:
    pyrequests = None
from urllib.request import urlopen
from urllib.parse import urlencode

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "951058071741-adnrookkkd1ldv13ci4vi1s0c6kvq132.apps.googleusercontent.com")


# ---------- Language helpers ----------
try:
    from langdetect import detect, DetectorFactory
    DetectorFactory.seed = 0
except Exception:
    detect = None
import re as _re
import time
_LANG_NAMES={
    "en":"English","zh-cn":"Simplified Chinese","zh-tw":"Traditional Chinese",
    "ja":"Japanese","ko":"Korean","fr":"French","ar":"Arabic","my":"Burmese",
    "hi":"Hindi","es":"Spanish"  # <-- added
}
_ARABIC_RANGES=("\u0600-\u06FF","\u0750-\u077F","\u08A0-\u08FF","\uFB50-\uFDFF","\uFE70-\uFEFF")
_CJK_RANGES=("\u4E00-\u9FFF",); _HIRAGANA="\u3040-\u309F"; _KATAKANA="\u30A0-\u30FF"; _HANGUL="\uAC00-\uD7AF"; _MY="\u1000-\u109F"
_ar=_re.compile(f"[{''.join(_ARABIC_RANGES)}]"); _cjk=_re.compile(f"[{''.join(_CJK_RANGES)}]"); _hi=_re.compile(f"[{_HIRAGANA}]"); _ka=_re.compile(f"[{_KATAKANA}]"); _ha=_re.compile(f"[{_HANGUL}]"); _mm=_re.compile(f"[{_MY}]")
def detect_lang_simple(text:str)->str:
    if not text: return "en"
    t=text.strip()
    if _mm.search(t): return "my"
    if _ar.search(t): return "ar"
    if _ha.search(t): return "ko"
    if _hi.search(t) or _ka.search(t): return "ja"
    if _cjk.search(t): return "zh-cn"
    if detect:
        try:
            c=detect(t); return "zh-cn" if c=="zh" else c
        except Exception: pass
    return "en"
def _lang_name(code:str)->str: return _LANG_NAMES.get(code,"the user’s language")
def system_prompt_for(code:str)->str:
    return f"You are a concise cybersecurity assistant. Always reply in {_lang_name(code)}. If the user switches languages mid-chat, mirror the latest user message language."

# ---------- HTTP/VT/AI ----------
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import torch, numpy as np
from PIL import Image as PILImage, ExifTags
from transformers import AutoImageProcessor, AutoModelForImageClassification
import cv2

from flask_cors import CORS
try:
    import ollama
except Exception:
    ollama=None

from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import jwt, chromadb
from chromadb.utils import embedding_functions

# ---------- Optional message encryption (unchanged) ----------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM=None
def _derive_key()->bytes:
    raw=os.getenv("NEXUS_ENC_KEY","")
    if raw:
        try: return base64.urlsafe_b64decode(raw+"===")
        except Exception:
            try: return bytes.fromhex(raw)
            except Exception: pass
    return hashlib.sha256(os.getenv("SECRET_KEY","devsecret").encode("utf-8")).digest()
ENC_KEY=_derive_key()
def encrypt_text(plaintext:str)->str:
    if not plaintext: return ""
    if AESGCM is None:
        return "b64:"+base64.urlsafe_b64encode(plaintext.encode("utf-8")).decode("ascii")
    aes=AESGCM(ENC_KEY); nonce=secrets.token_bytes(12)
    ct=aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return "gcm:"+base64.urlsafe_b64encode(nonce+ct).decode("ascii")
def decrypt_text(ciphertext:str)->str:
    if not ciphertext: return ""
    if ciphertext.startswith("gcm:") and AESGCM is not None:
        blob=base64.urlsafe_b64decode(ciphertext[4:].encode("ascii")); nonce,ct=blob[:12],blob[12:]
        return AESGCM(ENC_KEY).decrypt(nonce, ct, None).decode("utf-8","replace")
    if ciphertext.startswith("b64:"):
        try: return base64.urlsafe_b64decode(ciphertext[4:].encode("ascii")).decode("utf-8","replace")
        except Exception: return ""
    return ciphertext

# ---------- App config ----------
BASE_DIR=Path(__file__).parent.resolve()
app=Flask(__name__, template_folder="templates", static_folder="static")
CORS(app, supports_credentials=True)
UPLOAD_FOLDER=BASE_DIR/"uploads"; UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
app.config["UPLOAD_FOLDER"]=str(UPLOAD_FOLDER)

ALLOWED_EXTENSIONS = {
    # Documents
    "txt", "doc", "docx", "pdf", "ppt", "pptx", "xls", "xlsx", "csv", "json", "html", "htm", "xml", "md",

    # Images
    "jpg", "jpeg", "png", "gif", "bmp", "tiff", "ico", "svg", "psd", "ai", "eps", "indd",

    # Audio
    "mp3", "wav", "m4a", "aac", "ogg", "wma", "flac",

    # Video
    "mp4", "webm", "mkv", "wmv", "flv", "avi", "mov", "mpeg", "mpg", "3gp", "3g2",
    "rmvb", "rm", "vob", "ts", "m4v", "m2ts", "mts",

    # Archives
    "zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "tbz2", "xz", "iso", "cab", "dmg",

    # Executables / Scripts (for scanning!)
    "exe", "msi", "apk", "ipa", "bat", "cmd", "sh", "bin", "elf", "deb", "rpm", "jar", "class", "swf",

    # Disguised double extensions (real-world malware)
    "pdf.exe", "docx.exe", "pptx.exe", "xlsx.exe", "zip.exe", "rar.exe", "7z.exe",

    # Fonts
    "ttf", "otf", "woff", "woff2", "eot"
}

IMAGE_EXTS={"jpg","jpeg","png"}; VIDEO_EXTS={"mp4","webm","x-m4v"}

REQUEST_MAX=150*1024*1024; PER_FILE_MAX=80*1024*1024
app.config["MAX_CONTENT_LENGTH"]=REQUEST_MAX

VT_API_KEY=os.getenv("VT_API_KEY","")
AI_IMG_MODEL_1=os.getenv("AI_IMG_MODEL_1","Ateeqq/ai-vs-human-image-detector")
AI_IMG_MODEL_2=os.getenv("AI_IMG_MODEL_2","prithivMLmods/deepfake-detector-model-v1")
AI_HARD_THRES=float(os.getenv("AI_HARD_THRES","0.80")); REAL_HARD_THRES=float(os.getenv("REAL_HARD_THRES","0.40"))
FRAME_SAMPLES=int(os.getenv("FRAME_SAMPLES","16"))
DEVICE=torch.device("cuda" if torch.cuda.is_available() else "cpu")

OLLAMA_MODELS=[m.strip() for m in os.getenv("OLLAMA_MODELS","llama3.2:3b").split(",") if m.strip()]
REQUIRE_OLLAMA=bool(int(os.getenv("REQUIRE_OLLAMA","1")))

SECRET=os.getenv("SECRET_KEY","devsecret")
JWT_ISSUER="nexus-bot"; JWT_EXP_MIN=int(os.getenv("JWT_EXP_MIN","10080"))
PERSIST_DIR=os.getenv("CHROMA_DIR", str(BASE_DIR/"chroma_data")); Path(PERSIST_DIR).mkdir(parents=True, exist_ok=True)

CHAT_GREETING=os.getenv("CHAT_GREETING","Hello! I’m **Nexus Bot**. Ask me about cybersecurity threats, best practices, and staying safe online.")

# ---------- Chroma ----------
chroma_client=chromadb.PersistentClient(path=PERSIST_DIR)
users_col=chroma_client.get_or_create_collection(name="users", embedding_function=None)
embed_fn=embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
messages_col=chroma_client.get_or_create_collection(name="messages", embedding_function=embed_fn)
logs_col=chroma_client.get_or_create_collection(name="audit_logs", embedding_function=None)

ALLOWED_INCLUDES={"metadatas","documents","embeddings"}
def chroma_get_compat(collection, where:dict, **kwargs):
    def _clean(kw):
        kk=dict(kw); inc=kk.get("include")
        if inc is not None: kk["include"]=[x for x in inc if x in ALLOWED_INCLUDES]
        return kk
    def _nopage(kw): kk=dict(kw); kk.pop("limit",None); kk.pop("offset",None); return kk
    def _try(w, kw):
        try: return collection.get(where=w, **kw)
        except (TypeError,ValueError): pass
        try: return collection.get(where=w, **_nopage(kw))
        except (TypeError,ValueError): return None
    kw=_clean(kwargs)
    v1=where
    v2={"$and":[{k:{"$eq":(v.get("$eq") if isinstance(v,dict) and "$eq" in v else v)}} for k,v in where.items()]}
    v3={"$and":[{k:(v.get("$eq") if isinstance(v,dict) and "$eq" in v else v)} for k,v in where.items()]}
    v4={k:(v.get("$eq") if isinstance(v,dict) and "$eq" in v else v) for k,v in where.items()}
    for w in (v1,v2,v3,v4):
        got=_try(w,kw)
        if got is not None: return got
    return collection.get(where=v4, **_nopage(kw))

# ---------- JSON error handler ----------
from werkzeug.exceptions import HTTPException
@app.errorhandler(Exception)
def _json_errors(e):
    if isinstance(e, HTTPException): return e
    return jsonify({"ok":False,"error":f"Server error: {type(e).__name__}"}), 500

# ---------- HTTP session ----------
def build_session()->requests.Session:
    s=requests.Session(); s.trust_env=True
    retry=Retry(total=3, connect=3, read=3, backoff_factor=0.6,
                status_forcelist=[429,500,502,503,504],
                allowed_methods=frozenset(["GET","POST"]))
    ad=HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
    s.mount("https://", ad); s.mount("http://", ad)
    s.headers.update({"User-Agent":"nexus-bot-backend/1.2"})
    return s
SESSION=build_session()

# ---------- VirusTotal ----------
def vt_enabled()->bool: return bool(VT_API_KEY)
def vt_headers()->Dict[str,str]: return {"x-apikey": VT_API_KEY}
def vt_url_id(url:str)->str: return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")
def vt_scan_url(url:str)->Tuple[Optional[int],Optional[int]]:
    if not vt_enabled(): return None,None
    try:
        rid=vt_url_id(url)
        r=SESSION.get(f"https://www.virustotal.com/api/v3/urls/{rid}", headers=vt_headers(), timeout=20)
        if r.status_code==200:
            stats=r.json()["data"]["attributes"]["last_analysis_stats"]
            return int(stats.get("malicious",0)), int(sum(stats.values()))
        sub=SESSION.post("https://www.virustotal.com/api/v3/urls", headers=vt_headers(), data={"url":url}, timeout=20)
        if sub.status_code!=200: return None,None
        analysis_id=sub.json()["data"]["id"]
        for _ in range(10):
            rr=SESSION.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=vt_headers(), timeout=20)
            if rr.status_code==200:
                attrs=rr.json()["data"]["attributes"]
                if attrs.get("status")=="completed":
                    stats=attrs.get("stats",{})
                    return int(stats.get("malicious",0)), int(sum(stats.values()))
            time.sleep(3)
        return None,None
    except Exception:
        return None,None
def sha256_file(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1<<20), b""): h.update(chunk)
    return h.hexdigest()
def vt_scan_file(path:Path)->Tuple[Optional[int],Optional[int]]:
    if not vt_enabled(): return None,None
    try:
        file_hash=sha256_file(path)
        r=SESSION.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=vt_headers(), timeout=20)
        if r.status_code==200:
            stats=r.json()["data"]["attributes"]["last_analysis_stats"]
            return int(stats.get("malicious",0)), int(sum(stats.values()))
        with path.open("rb") as f:
            files={"file":(path.name, f)}
            up=SESSION.post("https://www.virustotal.com/api/v3/files", headers=vt_headers(), files=files, timeout=180)
        if up.status_code!=200: return None,None
        analysis_id=up.json()["data"]["id"]
        for _ in range(12):
            rr=SESSION.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=vt_headers(), timeout=20)
            if rr.status_code==200:
                attrs=rr.json()["data"]["attributes"]
                if attrs.get("status")=="completed":
                    stats=attrs.get("stats",{})
                    return int(stats.get("malicious",0)), int(sum(stats.values()))
            time.sleep(5)
        return None,None
    except Exception:
        return None,None

# ---------- AI image/video helpers ----------
AI_LABELS={"ai","fake","synthetic","generated"}; REAL_LABELS={"hum","human","real","authentic"}
class ImgDetector:
    def __init__(self, model_name:str)->None:
        self.proc=AutoImageProcessor.from_pretrained(model_name)
        self.model=AutoModelForImageClassification.from_pretrained(model_name).to(DEVICE).eval()
        raw=getattr(self.model.config,"id2label",None) or {}
        self.id2label={int(k):str(v).strip().lower() for k,v in raw.items()}
        self.ai_idx=None
        for i,lab in self.id2label.items():
            if any(tok in lab for tok in AI_LABELS): self.ai_idx=i
    def ai_prob(self, pil:PILImage.Image)->float:
        inputs=self.proc(images=pil, return_tensors="pt").to(DEVICE)
        with torch.no_grad(): out=self.model(**inputs)
        probs=torch.softmax(out.logits, dim=-1)[0].tolist()
        if self.ai_idx is None:
            idx=int(np.argmax(probs)); lab=self.id2label.get(idx,"")
            return float(probs[idx]) if any(t in lab for t in AI_LABELS) else 1.0-float(probs[idx])
        return float(probs[self.ai_idx])
DETECTORS:List[ImgDetector]=[]
def load_detectors():
    if DETECTORS: return
    try: DETECTORS.append(ImgDetector(AI_IMG_MODEL_1))
    except Exception as e: print("Failed to load model 1:", e)
    if AI_IMG_MODEL_2:
        try: DETECTORS.append(ImgDetector(AI_IMG_MODEL_2))
        except Exception as e: print("Failed to load model 2:", e)
GEN_SW=["stable diffusion","midjourney","dall-e","dalle","imagen","novelai","leonardo","flux.","sdxl","generative","ai picture","ai image"]
def extract_exif_flags(path:Path)->Tuple[bool,bool,bool,str]:
    try:
        img=PILImage.open(str(path)); ex=img._getexif()
        if not ex: return (False,False,False,"")
        tags={ExifTags.TAGS.get(k,k):v for k,v in ex.items()}
        make=str(tags.get("Make","") or ""); model=str(tags.get("Model","") or ""); dt=str(tags.get("DateTimeOriginal","") or "")
        soft=str(tags.get("Software","") or "").lower(); gen=any(k in soft for k in GEN_SW)
        return (bool(make or model), bool(dt), gen, soft or "")
    except Exception:
        return (False,False,False,"")
def ensemble_ai_prob_for_image(path:Path):
    load_detectors()
    if not DETECTORS: return None, {"error":"No detectors loaded"}
    img=PILImage.open(str(path)).convert("RGB")
    probs=[]
    for det in DETECTORS:
        try: probs.append(det.ai_prob(img))
        except Exception as e: print("inference error:", e)
    if not probs: return None, {"error":"Inference failed"}
    p=float(np.mean(probs))
    has_cam,has_dt,gen,_=extract_exif_flags(path)
    if has_cam and has_dt: p=max(0.0,p-0.15)
    if gen: p=min(1.0,p+0.20)
    return p, {"models":len(probs), "p_raw":p, "p_adj":p}
def sample_video_frames(path:Path, k:int=16)->List[PILImage.Image]:
    cap=cv2.VideoCapture(str(path)); 
    if not cap.isOpened(): raise RuntimeError("Cannot open video")
    total=int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 0
    idxs=list(range(0,total,max(1,total//max(1,k))))[:k] if total>0 else list(range(0,k))
    frames=[]
    for i in idxs:
        cap.set(cv2.CAP_PROP_POS_FRAMES,i); ok,frame=cap.read()
        if not ok: continue
        frames.append(PILImage.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)))
    cap.release(); return frames
def ensemble_ai_prob_for_video(path:Path):
    load_detectors()
    if not DETECTORS: return None, {"error":"No detectors loaded"}
    frames=sample_video_frames(path, FRAME_SAMPLES)
    if not frames: return None, {"error":"No frames read"}
    per=[]
    for f in frames:
        probs=[]
        for det in DETECTORS:
            try: probs.append(det.ai_prob(f))
            except Exception as e: print("frame inference error:", e)
        if probs: per.append(float(np.mean(probs)))
    if not per: return None, {"error":"All frame inferences failed"}
    p=float(np.mean(per))
    return p, {"frames_used":len(per), "p_raw":p, "p_adj":p,
               "frac_flag": float(sum(x>=AI_HARD_THRES for x in per))/len(per)}
def verdict_sentence_from_prob(p:float, ctx:str, extra:Optional[Dict[str,Any]]=None)->str:
    pct=int(round(p*100))
    if p>=AI_HARD_THRES: msg=f"{ctx} is likely AI-generated ({pct}%)."
    elif p<=REAL_HARD_THRES: msg=f"{ctx} is likely real ({pct}%)."
    else: msg=f"{ctx} is inconclusive ({pct}%)."
    if isinstance(extra,dict):
        tail=[]; 
        if "models" in extra: tail.append(f"models used: {extra['models']}")
        if "frames_used" in extra: tail.append(f"frames: {extra['frames_used']}")
        if "frac_flag" in extra: tail.append(f"frame AI hits: {int(extra['frac_flag']*100)}%")
        if tail: msg += " " + " ".join(tail) + "."
    return msg


# ---------- Live Voice / Risk Guard ----------
# Dynamic, intent-aware safety gate. Allows general knowledge/defensive questions,
# blocks requests for instructions to commit wrongdoing (illegal hacking, malware creation, etc.).
def _safe_strip_json(text: str) -> str:
    import re, json
    if not text:
        return "{}"
    # try to extract the first JSON object in text
    m = re.search(r"\{[\s\S]*?\}", text)
    return m.group(0) if m else "{}"

def llm_safety_gate(text: str) -> dict:
    t = (text or "").strip()
    out = {"block": False, "reason": "allow", "categories": []}
    try:
        # Prefer model-based classification when available
        if ollama is not None:
            prompt = (
                "Classify the user's intent for safety.\n"
                "BLOCK only if they ask for instructions that facilitate wrongdoing "
                "(e.g., how to hack, launch ddos, build malware, craft exploit, bypass auth, phish someone).\n"
                "ALLOW for definitions, history, educational overviews, detection, mitigation, prevention, or policy/compliance.\n"
                "Return strict JSON with keys: block (true|false), reason (string), categories (array of short strings).\n\n"
                f"User: {t}"
            )
            resp = ollama.chat(
                model=OLLAMA_MODELS[0],
                messages=[
                    {"role": "system", "content": "You are a safety classifier. Output JSON only."},
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.0},
            )
            raw = (resp.get("message") or {}).get("content", "") or ""
            js = json.loads(_safe_strip_json(raw))
            if isinstance(js, dict):
                js.setdefault("block", False)
                js.setdefault("reason", "allow")
                js.setdefault("categories", [])
                out = js
                # Normalize
                out["block"] = bool(out.get("block"))
                if out["block"] and not out.get("reason"):
                    out["reason"] = "safety policy"
                return out
    except Exception:
        pass

    # Heuristic fallback (narrow, avoids over-blocking). Only block "how-to" style harm.
    lower = t.lower()
    HOWTO = ("how to", "how can i", "step by step", "guide me", "tutorial", "write code", "script", "payload", "exploit", "bypass", "crack", "breach", "break into", "launch", "execute")
    HARM = ("ddos", "botnet", "phishing kit", "ransomware", "malware", "virus", "keylogger", "backdoor", "sql injection", "xss", "privilege escalation", "attack", "hack")
    DEFENSE_HINTS = ("what is", "definition", "explain", "educational", "for school", "mitigate", "prevention", "detect", "detection", "defend", "protect", "avoid", "awareness", "ethics", "policy", "legal", "lawful", "best practice")
    if any(h in lower for h in DEFENSE_HINTS):
        return out  # allow
    if any(h in lower for h in HOWTO) and any(b in lower for b in HARM):
        return {"block": True, "reason": "instructional wrongdoing", "categories": ["cybercrime"]}
    return out  # default allow
# ---------- Helpers ----------
def allowed_file(filename:str)->bool:
    return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS
def file_ext(filename:str)->str:
    return filename.rsplit(".",1)[1].lower() if "." in filename else ""
def normalize_url(url:str)->str:
    return url if re.match(r"^[a-z]+://", url, re.I) else "http://" + url

def make_token(user_id:str, email:str, role:str="user")->str:
    now=datetime.datetime.utcnow()
    payload={"sub":user_id,"email":email,"role":role,"iss":JWT_ISSUER,"iat":now,"exp":now+datetime.timedelta(minutes=JWT_EXP_MIN)}
    return jwt.encode(payload, SECRET, algorithm="HS256")

def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth=request.headers.get("Authorization","")
        if not auth.startswith("Bearer "): return jsonify({"error":"Missing token"}), 401
        token=auth.split(" ",1)[1].strip()
        try:
            payload=jwt.decode(token, SECRET, algorithms=["HS256"], issuer=JWT_ISSUER)
        except Exception:
            return jsonify({"error":"Invalid token"}), 401
        request.user={"id":payload["sub"],"email":payload["email"],"role":payload.get("role","user")}
        return fn(*args, **kwargs)
    return wrapper

def try_parse_user():
    auth=request.headers.get("Authorization","")
    if not auth.startswith("Bearer "): return (None, None)
    token=auth.split(" ",1)[1].strip()
    try:
        payload=jwt.decode(token, SECRET, algorithms=["HS256"], issuer=JWT_ISSUER)
        return (payload.get("sub"), payload.get("email"))
    except Exception:
        return (None, None)

def get_user_record(uid:str):
    rec=users_col.get(ids=[uid], include=["metadatas","documents","embeddings"])
    meta=(rec.get("metadatas") or [{}])[0] or {}
    doc=(rec.get("documents") or [None])[0]
    emb=(rec.get("embeddings") or [[0.0]])[0]
    return meta, doc, emb

def update_user_metadata(uid:str, updates:dict):
    meta, doc, emb = get_user_record(uid)
    meta.update(updates)
    try:
        users_col.update(ids=[uid], metadatas=[meta])
    except Exception:
        try:
            users_col.upsert(ids=[uid], metadatas=[meta], documents=[doc or meta.get("email","")], embeddings=[emb])
        except Exception:
            try: users_col.delete(ids=[uid])
            except Exception: pass
            users_col.add(ids=[uid], metadatas=[meta], documents=[doc or meta.get("email","")], embeddings=[emb])


def upsert_google_user(google_sub: str, email: str, name: str = "", picture: str = "") -> str:
    uid = f"google:{google_sub}"
    meta, doc, emb = get_user_record(uid)
    meta.update({
        "email": email or meta.get("email",""),
        "name": name or meta.get("name",""),
        "picture": picture or meta.get("picture",""),
        "provider": "google",
        "updated_at": datetime.datetime.utcnow().isoformat()
    })
    if not doc:
        doc = email or uid
    # FIX: avoid NumPy ambiguous truth value on empty arrays
    if emb is None or (hasattr(emb,'size') and emb.size == 0) or (hasattr(emb,'__len__') and len(emb) == 0):
        emb = [0.0]
    try:
        users_col.upsert(ids=[uid], metadatas=[meta], documents=[doc], embeddings=[emb])
    except Exception:
        try:
            users_col.add(ids=[uid], metadatas=[meta], documents=[doc], embeddings=[emb])
        except Exception:
            pass
    return uid

def verify_google_id_token(id_token_str: str):
    """Verify a Google ID token and return dict with sub/email/name/picture/email_verified."""
    last_error = None
    # Preferred: google-auth library
    if google_id_token and google_requests:
        try:
            info = google_id_token.verify_oauth2_token(id_token_str, google_requests.Request(), GOOGLE_CLIENT_ID)
            aud = info.get("aud")
            aud_ok = (aud == GOOGLE_CLIENT_ID) or (isinstance(aud,(list,tuple,set)) and GOOGLE_CLIENT_ID in aud)
            if not aud_ok:
                raise ValueError(f"aud mismatch (got {aud!r})")
            return {
                "sub": info.get("sub"),
                "email": info.get("email"),
                "name": info.get("name"),
                "picture": info.get("picture"),
                "email_verified": bool(info.get("email_verified")),
                "iss": info.get("iss"),
            }
        except Exception as e:
            last_error = e
    # Fallback: tokeninfo
    try:
        if pyrequests:
            r = pyrequests.get("https://oauth2.googleapis.com/tokeninfo", params={"id_token": id_token_str}, timeout=10)
            if r.status_code != 200:
                raise ValueError(f"tokeninfo HTTP {r.status_code}")
            info = r.json()
        else:
            with urlopen("https://oauth2.googleapis.com/tokeninfo?" + urlencode({"id_token": id_token_str})) as resp:
                import json as _json
                info = _json.loads(resp.read().decode("utf-8"))
        aud = info.get("aud")
        aud_ok = (aud == GOOGLE_CLIENT_ID) or (isinstance(aud,(list,tuple,set)) and GOOGLE_CLIENT_ID in aud)
        if not aud_ok:
            raise ValueError(f"aud mismatch (got {aud!r})")
        return {
            "sub": info.get("sub"),
            "email": info.get("email"),
            "name": info.get("name"),
            "picture": info.get("picture"),
            "email_verified": (info.get("email_verified") in ("true","1",True)),
            "iss": info.get("iss"),
        }
    except Exception as e2:
        if last_error:
            raise last_error
        raise e2
def has_scanning_consent_uid(uid:str)->bool:
    if not uid: return False
    meta,_,_=get_user_record(uid)
    return bool(meta.get("consent_scanning"))

def has_scanning_consent_request()->bool:
    uid,_=try_parse_user()
    if uid and has_scanning_consent_uid(uid): return True
    if request.cookies.get("consent_scanning","0") == "1": return True
    if str(request.headers.get("X-Consent-Scanning","")).lower() in ("1","true","yes"): return True
    return False

def save_message(uid:str, chat_id:str, role:str, content:str, extra_meta:Optional[Dict[str,Any]]=None):
    try:
        embedding=embed_fn([content])[0]
    except Exception:
        embedding=[0.0]
    meta={"user_id":uid,"chat_id":chat_id,"role":role,"ts":datetime.datetime.utcnow().isoformat(),"enc":"gcm" if AESGCM else "b64"}
    if extra_meta: meta.update(extra_meta)
    mid=f"{chat_id}:{role}:{uuid.uuid4().hex}"
    messages_col.add(ids=[mid], documents=[encrypt_text(content)], metadatas=[meta], embeddings=[embedding])
    return mid
def decrypt_if_needed(doc:str)->str:
    try: return decrypt_text(doc)
    except Exception: return doc or ""

# ---------- Titles/chat utils ----------
def make_title_from_text(text:str, max_len:int=48)->str:
    s=re.sub(r"\s+"," ",(text or "").strip())
    return s if s and len(s)<=max_len else (s[:max_len].rstrip()+"…") if s else "Untitled Chat"
def add_title_message(uid:str, chat_id:str, title:str, source:str="auto", reason:str="default"):
    save_message(uid, chat_id, "title", title, extra_meta={"title_source":source,"title_reason":reason})
def get_latest_title(uid:str, chat_id:str)->Dict[str,Any]:
    try:
        rec=chroma_get_compat(messages_col, {"user_id":{"$eq":uid},"chat_id":{"$eq":chat_id},"role":{"$eq":"title"}}, include=["metadatas","documents"], limit=1000)
        metas=rec.get("metadatas",[]) or []; docs=rec.get("documents",[]) or []; pairs=list(zip(metas,docs))
        if not pairs: raise RuntimeError("empty")
    except Exception:
        try: rec=messages_col.get(include=["metadatas","documents"], limit=10000)
        except Exception: rec=messages_col.get(include=["metadatas","documents"])
        pairs=[(m,d) for m,d in zip(rec.get("metadatas",[]) or [], rec.get("documents",[]) or [])
               if m.get("user_id")==uid and m.get("chat_id")==chat_id and m.get("role")=="title"]
    latest={}
    for m,d in pairs:
        ts=str(m.get("ts",""))
        if not latest or ts>latest["ts"]:
            latest={"title":decrypt_if_needed(d).strip(),"source":m.get("title_source","auto"),"ts":ts}
    return latest
def count_user_messages(uid:str, chat_id:str)->int:
    try:
        rec=chroma_get_compat(messages_col, {"user_id":{"$eq":uid},"chat_id":{"$eq":chat_id},"role":{"$eq":"user"}}, include=[], limit=10000)
        return len(rec.get("ids",[]) or [])
    except Exception:
        try: rec=messages_col.get(include=["metadatas"], limit=10000)
        except Exception: rec=messages_col.get(include=["metadatas"])
        return sum(1 for m in (rec.get("metadatas",[]) or [])
                   if m.get("user_id")==uid and m.get("chat_id")==chat_id and m.get("role")=="user")
def get_titles_map(uid:str)->Dict[str,str]:
    try:
        rec=chroma_get_compat(messages_col, {"user_id":{"$eq":uid},"role":{"$eq":"title"}}, include=["metadatas","documents"], limit=10000)
        metas=rec.get("metadatas",[]) or []; docs=rec.get("documents",[]) or []; pairs=list(zip(metas,docs))
        if not pairs: raise RuntimeError("empty")
    except Exception:
        try: rec=messages_col.get(include=["metadatas","documents"], limit=10000)
        except Exception: rec=messages_col.get(include=["metadatas","documents"])
        pairs=[(m,d) for m,d in zip(rec.get("metadatas",[]) or [], rec.get("documents",[]) or [])
               if m.get("user_id")==uid and m.get("role")=="title"]
    out={}
    for m,d in pairs:
        cid=m.get("chat_id"); ts=str(m.get("ts",""))
        if not cid: continue
        if cid not in out or ts>out[cid]["ts"]:
            out[cid]={"title":decrypt_if_needed(d).strip() or "Untitled Chat","ts":ts}
    return {cid:v["title"] for cid,v in out.items()}
def fetch_message_ids_for_chat(uid:str, chat_id:str)->List[str]:
    try:
        rec=chroma_get_compat(messages_col, {"user_id":{"$eq":uid},"chat_id":{"$eq":chat_id}}, include=[], limit=10000)
        ids=rec.get("ids",[]); 
        if ids: return ids
    except Exception: pass
    try: rec=messages_col.get(include=["metadatas"])
    except Exception: rec={"ids":[], "metadatas":[]}
    ids=[]
    for _id,meta in zip(rec.get("ids",[]) or [], rec.get("metadatas",[]) or []):
        if isinstance(meta,dict) and meta.get("user_id")==uid and meta.get("chat_id")==chat_id: ids.append(_id)
    return ids

def _classify_risk(mal: int, total: int):
    total = int(total or 0); mal = int(mal or 0)
    ratio = (mal / total) if total else 0.0
    if mal == 0: label = "Low"
    elif mal >= 10 or ratio >= 0.20: label = "High"
    elif mal >= 3 or ratio >= 0.05: label = "Medium"
    else: label = "Low (suspicious)"
    return {"label": label, "ratio": ratio}

_SUS_KEYWORDS = ("login","verify","secure","update","password","wallet","invoice","attachment","gift","tracking")
_SUS_TLDS = (".zip",".mov")
_IPv4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

def _url_heuristics(u: str):
    try:
        p = urlparse(u if re.match(r"^[a-z]+://", u, re.I) else "http://" + u)
    except Exception:
        p = urlparse("http://" + u)
    host = (p.hostname or "").lower()
    issues = []
    if _IPv4_RE.match(host): issues.append("Uses a raw IP address instead of a domain (phishing red flag).")
    if host.count('-') >= 2: issues.append("Domain contains multiple hyphens.")
    if host.count('.') >= 3: issues.append("Very deep subdomain — may hide the real registrant.")
    if "@" in u: issues.append("URL contains '@' which can mask the real destination.")
    if len(u) > 120: issues.append("Unusually long URL path/query.")
    if any(host.endswith(tld) for tld in _SUS_TLDS): issues.append(f"Top-level domain appears frequently in phishing ({', '.join(_SUS_TLDS)}).")
    if "xn--" in host: issues.append("Domain uses punycode (possible IDN homograph).")
    lower = u.lower()
    hits = [kw for kw in _SUS_KEYWORDS if kw in lower]
    if hits: issues.append("Suspicious keywords present: " + ", ".join(sorted(set(hits))))
    return issues

def _build_paragraphs(url: str, mal: int, total: int, risk_label: str, ratio: float):
    pct = f"{ratio*100:.1f}%"
    heur = _url_heuristics(url)
    heur_line = "None observed." if not heur else ("; ".join(heur) + ".")
    if mal == 0:
        first = (f"VirusTotal scanned the link against {total} engines and **none** flagged it as malicious. "
                 f"Current risk is **{risk_label}** (flag rate {pct}).")
    else:
        first = (f"VirusTotal scanned the link against {total} engines and **{mal}** reported indicators of harm. "
                 f"Overall risk is **{risk_label}** (flag rate {pct}). Multiple agreeing engines generally mean higher confidence.")
    return [
        f"**Scan summary — {url}**",
        first,
        "### What this means\n"
        "VirusTotal aggregates results from many AV/URL reputation engines. A detection indicates the URL may host malware, "
        "be a phishing page, or distribute unwanted software. False positives happen, but they are less likely when several engines agree.",
        "### Quick sanity checks on the URL\n" + heur_line,
        "### Recommended actions\n"
        "- Treat the link with caution. Do **not** enter credentials.\n"
        "- If you must visit, use a patched VM/sandbox and type the root domain manually.\n"
        "- Verify the sender via a separate channel. If credentials were entered, **change passwords immediately** and enable 2FA.",
        "### Optional next steps\n"
        "- Re-scan later; engines update over time.\n"
        "- Check domain WHOIS/age and certificate issuer; block at email/web gateway if Medium/High and not business-critical."
    ]

def _suggest_prompts(url: str):
    host = (urlparse(url if re.match(r'^[a-z]+://', url, re.I) else 'http://'+url).hostname) or url
    return [
        f"Draft a short warning to my team about this link ({host}) and what to do if they clicked.",
        f"Explain how to verify if {host} is the legitimate site for the brand it resembles.",
        "Give me a safe step-by-step to check a suspicious link in a VM.",
        "Create an incident note template (URL, sender, time seen, VT score, user impact, actions taken).",
        "List controls to reduce phishing risk (email security, DNS filtering, MFA, FIDO keys).",
        f"Make a checklist for evaluating login pages similar to {host} (TLS, domain spelling, context).",
    ]





_EXEC_EXT = {"exe","msi","apk","ipa","bat","cmd","sh","bin","elf","deb","rpm","jar","class","swf"}
_OFFICE_EXT = {"doc","docx","dotm","docm","xls","xlsx","xlsm","ppt","pptx","pptm"}
_PDF_EXT = {"pdf"}
_ARCHIVE_EXT = {"zip","rar","7z","tar","gz","tgz","bz2","tbz2","xz","iso","cab","dmg"}
_SCRIPT_EXT = {"js","vbs","ps1","psm1","py","rb","pl"}  # may not all be in ALLOWED_EXTENSIONS but used for heuristics
_DOUBLE_EXT_RE = _re.compile(r"\.([a-z0-9]{1,4})\.(exe|scr|bat|cmd|js)$", _re.I)

def _fmt_size(n: int) -> str:
    units = ["B","KB","MB","GB","TB"]
    if not n: return "0 B"
    i = int(math.floor(math.log(n, 1024)))
    return f"{n / (1024 ** i):.1f} {units[i]}"

def _file_category(filename: str, ext: str):
    """Return (category, heuristics[]) based on extension and name."""
    name_l = filename.lower()
    heur = []
    cat = "document"

    if ext in _EXEC_EXT:
        cat = "executable"
        if _DOUBLE_EXT_RE.search(name_l): heur.append("Filename looks like a double extension (e.g., *.pdf.exe).")
    elif ext in _OFFICE_EXT:
        cat = "office"
        if ext.endswith("m"): heur.append("Macro-enabled Office document — macros can run code.")
    elif ext in _PDF_EXT:
        cat = "pdf"
        if "invoice" in name_l or "payment" in name_l: heur.append("Common lure keywords in filename (invoice/payment).")
    elif ext in _ARCHIVE_EXT:
        cat = "archive"
        if "password" in name_l: heur.append("Password-protected archives bypass many gateway checks.")
    elif ext in IMAGE_EXTS:
        cat = "image"
    elif ext in VIDEO_EXTS:
        cat = "video"
    elif ext in _SCRIPT_EXT:
        cat = "script"

    if len(filename) > 80: heur.append("Unusually long filename.")
    return cat, heur

def _build_file_paragraphs(filename: str, ext: str, size_bytes: int,
                           vt_mal: int, vt_total: int, risk_label: str, ratio: float,
                           media_sentence: str | None = None,
                           zip_flag: str | None = None):
    size_txt = _fmt_size(size_bytes or 0)
    vt_line = ("none flagged it as malicious"
               if vt_mal == 0 else f"{vt_mal} engine(s) reported indicators of harm")
    first = (f"VirusTotal scanned **{filename}** ({size_txt}) with {vt_total} engines and {vt_line}. "
             f"Overall risk is **{risk_label}** (flag rate {ratio*100:.1f}%).")

    cat, heur = _file_category(filename, ext)
    cat_blurb = {
        "executable": "Executable files can install programs or run arbitrary code when opened.",
        "office": "Office files may include macros or embedded objects that execute code.",
        "pdf": "PDFs can contain scripts and links; readers with vulnerabilities may be exploited.",
        "archive": "Archives may hide malicious files or attempt decompression attacks.",
        "image": "Images are usually safe to open",
        "video": "Videos are less commonly malicious but may be used in scams or deepfakes.",
        "script": "Script files execute instructions and are high-risk if sourced from email/links.",
        "document": "Documents can contain links or embedded content; always verify the source."
    }.get(cat, "This file type may carry risk depending on how it’s opened.")

    heur_line = "None observed." if not heur else ("; ".join(heur) + ".")
    extra = []
    if zip_flag:
        extra.append(zip_flag)
    if media_sentence:
        extra.append(media_sentence)

    paragraphs = [
        f"**Scan summary — {filename}**",
        first,
        "### File type assessment\n"
        f"Detected type: **{cat.upper()}**. " + cat_blurb,
        "### Quick checks from filename/type\n" + heur_line,
        "### What the VirusTotal score means\n"
        "VirusTotal aggregates antivirus and reputation engines. Multiple agreeing detections increase confidence. "
        "Absence of detections doesn’t guarantee safety — new threats may not be flagged yet.",
        "### Recommended actions\n"
        "- Only open files from trusted senders. Verify via a separate channel.\n"
        "- For **executables/scripts**: do not run them unless required and verified; prefer a sandbox/VM.\n"
        "- For **Office/PDF**: disable macros; open in up-to-date viewers; avoid enabling external content.\n"
        "- If opened already, monitor the system and run endpoint scans; change credentials if prompted in the file."
    ]

    if extra:
        paragraphs.insert(3, "### Additional analysis\n" + "\n".join(f"- {x}" for x in extra))

    paragraphs.append(
        "### Optional next steps\n"
        "- Re-scan later; engines update over time.\n"
        "- Check the file’s hash in threat intel sources; block by hash if risky.\n"
        "- Keep OS and apps patched; use reputable endpoint protection."
    )
    return paragraphs



# ---------- tiny helpers (add near your other helpers) ----------
def _extract_models_used(info: dict) -> int:
    if not isinstance(info, dict):
        return 1
    for k in ("models_used", "models_count", "n_models", "votes"):
        if k in info:
            try:
                return max(1, int(info[k]))
            except Exception:
                pass
    for k in ("models", "scores", "details"):
        if k in info and isinstance(info[k], (list, tuple)) and len(info[k]) > 0:
            return len(info[k])
    return 1

def _ai_band(p_ai: float):
    if p_ai >= 0.70: return "High likelihood of AI-generated", "high_ai"
    if p_ai <= 0.30: return "Low likelihood of AI-generated (likely real)", "low_ai"
    return "Uncertain authenticity (mixed signals)", "uncertain"

def _why_bullets_from_info(info: dict):
    bullets = []
    if not isinstance(info, dict): return bullets
    if info.get("metadata_hint"): bullets.append("Metadata includes generator markers (e.g., prompts/seeds).")
    if info.get("camera_meta"): bullets.append("Camera EXIF present (Make/Model/Lens/DateTimeOriginal).")
    lap = info.get("laplacian_var")
    if lap is not None:
        try:
            lap = float(lap)
            if lap < 60: bullets.append("Very low micro-texture/edge detail (airbrushed look).")
            elif lap > 250: bullets.append("High micro-texture/edge detail (consistent with real photos).")
            else: bullets.append("Moderate texture/edges (not strongly indicative).")
        except Exception:
            pass
    faces = info.get("faces")
    if isinstance(faces, int): bullets.append(f"Detected {faces} face(s) in the image.")
    exif_keys = info.get("exif_keys") or info.get("exif") or []
    if isinstance(exif_keys, dict): exif_keys = list(exif_keys.keys())
    if isinstance(exif_keys, (list, tuple)) and exif_keys:
        bullets.append("EXIF keys present: " + ", ".join(map(str, exif_keys[:5])) + ("..." if len(exif_keys) > 5 else ""))
    for k in ("signals", "notes"):
        sigs = info.get(k)
        if isinstance(sigs, (list, tuple)) and sigs:
            bullets += [str(s) for s in sigs[:5]]
            break
    return bullets

def _build_image_paragraphs(filename: str, size_bytes: int,
                            p_ai: float, models_used: int, info: dict,
                            vt_mal: int | None, vt_total: int | None):
    pct = int(round(p_ai * 100))
    ai_label, band = _ai_band(p_ai)
    size_txt = _fmt_size(size_bytes or 0)
    headline = (
        f"**Authenticity assessment — {filename}**\n"
        f"Our analysis estimates this image has **{ai_label}** (**{pct}%**). "
        f"Models used: **{models_used}**."
    )
    vt_line = ("VirusTotal scan: unavailable in this run."
               if (vt_mal is None or vt_total is None)
               else (f"VirusTotal scan: {vt_mal}/{vt_total} engines flagged it."
                     if vt_mal > 0 else f"VirusTotal scan: 0/{vt_total} engines flagged it."))
    why = _why_bullets_from_info(info)
    why_block = "### Why this assessment\n" + ("\n".join(f"- {b}" for b in why) if why else "- No strong forensic signals detected.")
    meaning = ("### What this means\n"
               "AI-generated images can be highly convincing and used for impersonation, scams, or disinformation. "
               "A higher percentage suggests synthetic origin; a lower one suggests a natural photograph; mid-range is inconclusive.")
    if band == "high_ai":
        rec = ("### Recommended actions\n"
               "- Treat the image as **synthetic** unless independently verified.\n"
               "- Do not trust identity/authority claims based only on this image.\n"
               "- Request originals and corroborating sources; use reverse image search.\n"
               "- Escalate for manual review if used for access/approvals.")
    elif band == "low_ai":
        rec = ("### Recommended actions\n"
               "- Treat the image as **likely real**, but verify the **context** (who posted it, when, and why).\n"
               "- Check for simple manipulations (cropping/overlays) and confirm the source account.\n"
               "- For high-risk decisions (payments/access), require out-of-band confirmation.")
    else:
        rec = ("### Recommended actions\n"
               "- Consider the result **inconclusive**; seek additional evidence.\n"
               "- Ask for the original, full-resolution file and camera details.\n"
               "- Use multiple reverse image searches; inspect lighting/shadows/reflections.\n"
               "- Defer high-impact decisions until verification improves.")
    addl = ("### Additional analysis\n"
            f"- This image is likely {'AI-generated' if p_ai >= 0.5 else 'real'} ({pct}%). models used: {models_used}.\n"
            f"- File size: {size_txt}. {vt_line}")
    next_steps = ("### Optional next steps\n"
                  "- Re-run analysis on an uncompressed/original file.\n"
                  "- Compare EXIF against other images from the same source.\n"
                  "- Keep a review log with file hash and decision.")
    return [headline, meaning, why_block, rec, addl, next_steps]

def _build_video_paragraphs(filename: str, size_bytes: int,
                            p_ai: float | None, models_used: int, info: dict,
                            vt_mal: int | None, vt_total: int | None):
    size_txt = _fmt_size(size_bytes or 0)
    if p_ai is None:
        headline = f"**Authenticity assessment — {filename}**\nVideo AI analysis failed or unavailable."
        ai_line = "AI likelihood: unknown."
    else:
        pct = int(round(p_ai * 100))
        ai_label, band = _ai_band(p_ai)
        headline = (f"**Authenticity assessment — {filename}**\n"
                    f"Our analysis estimates this video has **{ai_label}** (**{pct}%**). "
                    f"Models used: **{models_used}**.")
        ai_line = f"This video is likely {'AI-generated' if p_ai >= 0.5 else 'real'} ({pct}%). models used: {models_used}."
    vt_line = ("VirusTotal scan: unavailable in this run."
               if (vt_mal is None or vt_total is None)
               else (f"VirusTotal scan: {vt_mal}/{vt_total} engines flagged it."
                     if vt_mal > 0 else f"VirusTotal scan: 0/{vt_total} engines flagged it."))
    why = _why_bullets_from_info(info)
    why_block = "### Why this assessment\n" + ("\n".join(f"- {b}" for b in why) if why else "- No strong forensic signals detected.")
    rec = ("### Recommended actions\n"
           "- Verify source account and posting context.\n"
           "- Look for lip-sync, eye-blink irregularities, hand/finger artifacts.\n"
           "- For identity claims, request live verification on a secure channel.")
    addl = ("### Additional analysis\n"
            f"- {ai_line}\n"
            f"- File size: {size_txt}. {vt_line}")
    next_steps = ("### Optional next steps\n"
                  "- Request original, uncompressed footage.\n"
                  "- Compare frames to known references; check audio/video sync.\n"
                  "- Keep a review log with file hash and decision.")
    return [headline, why_block, rec, addl, next_steps]
# ---------------------------------------------------------------




# ---------- Static pages ----------
@app.route("/")
def index():
    try: return render_template("index.html")
    except: return "Backend is running. Use POST /chat or GET /try?q=question", 200
    
@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/home")
def home_page():
    return render_template("home.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/profile.html")
def profile_page():
    return render_template("profile.html")

@app.route("/upload-profile.html")
def upload_profile_page():
    return render_template("upload_profile.html")

@app.route("/upload-photo.html")
def upload_photo_page():
    return render_template("upload_photo.html")

@app.route("/about.html")
def about_page():
    return render_template("about.html")

@app.route("/FAQ.html")
def faq_page():
    return render_template("FAQ.html")

@app.route("/term")
def term():
    return render_template("terms.html")

@app.route("/uploads/<path:filename>")
def serve_upload(filename): return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=False)

@app.route("/health")
def health():
    try: load_detectors()
    except Exception: pass
    try:
        ucount=len(users_col.get()["ids"]); mcount=len(messages_col.get()["ids"]); lcount=len(logs_col.get()["ids"])
    except Exception: ucount=mcount=lcount=0
    return jsonify({
        "detectors_loaded": len(DETECTORS),
        "device": str(DEVICE),
        "ollama_available": bool(ollama is not None),
        "ollama_models": OLLAMA_MODELS,
        "require_ollama": REQUIRE_OLLAMA,
        "virustotal_configured": bool(VT_API_KEY),
        "chroma":{"users":ucount,"messages":mcount,"logs":lcount,"persist_dir":PERSIST_DIR},
        "encryption":{"mode":"AES-256-GCM" if AESGCM else "Base64 (fallback)"},
    })

# ---------- Demo chat ----------
@app.route("/new_chat", methods=["POST"])
def new_chat():
    session_id=str(time.time())
    return jsonify({"response":"Hello! Add files or paste links, then press Upload & Scan.","session_id":session_id})

@app.route("/try")
def try_chat():
    q=request.args.get("q","").strip()
    if not q: return "Add ?q=your+question to the URL", 400
    lang=detect_lang_simple(q)
    if REQUIRE_OLLAMA and ollama is not None:
        try:
            resp=ollama.chat(model=OLLAMA_MODELS[0],
                             messages=[{"role":"system","content":system_prompt_for(lang)},
                                       {"role":"user","content":q}],
                             options={"temperature":0.2})
            msg=(resp.get("message") or {}).get("content") or ""
        except Exception as e:
            return (f"LLM error: {e}", 503)
        return f"<pre>{msg}</pre>", 200
    return f"<pre>{q}</pre>", 200

# ---------- Auth ----------
@app.post("/api/auth/register")
def api_register():
    try:
        data=request.json or {}
        name=(data.get("name") or "").strip()
        email=(data.get("email") or "").strip().lower()
        password=data.get("password") or ""
        if not name or not email or not password:
            return jsonify({"ok":False,"error":"Missing fields"}), 400
        rec=chroma_get_compat(users_col, {"email":{"$eq":email}}, include=["metadatas","ids"])
        if rec.get("ids"): return jsonify({"ok":False,"error":"Email already exists"}), 409
        uid=str(uuid.uuid4()); pwd_hash=generate_password_hash(password)
        users_col.add(ids=[uid], embeddings=[[0.0]], documents=[email],
                      metadatas=[{"email":email,"name":name,"password_hash":pwd_hash,"created_at":datetime.datetime.utcnow().isoformat(),
                                  "consent_scanning": False,"theme":"auto","lang":"en","role":"user"}])
        token=make_token(uid, email, role="user")
        return jsonify({"ok":True,"token":token,"user":{"id":uid,"email":email,"name":name}})
    except Exception as e:
        return jsonify({"ok":False,"error":f"Server error: {e.__class__.__name__}: {e}"}), 500


@app.post("/api/auth/google")
def api_auth_google():
    try:
        data = request.get_json(silent=True) or {}
        id_token_str = (data.get("id_token") or data.get("credential") or "").strip()
        if not id_token_str:
            return jsonify({"ok": False, "error": "Missing id_token"}), 400
        try:
            info = verify_google_id_token(id_token_str)
        except Exception as e:
            return jsonify({"ok": False, "error": f"Google verify failed: {type(e).__name__}: {str(e)}"}), 401
        sub = info.get("sub"); email = info.get("email") or ""; name = info.get("name") or ""; picture = info.get("picture") or ""
        uid = upsert_google_user(sub, email, name, picture)
        token = make_token(uid, email, role="user")
        update_user_metadata(uid, {"last_login_provider":"google","email_verified": bool(info.get("email_verified"))})
        return jsonify({"ok": True, "token": token, "profile": {"id": uid, "email": email, "name": name, "picture": picture}})
    except Exception as e:
        return jsonify({"ok": False, "error": f"Google auth failed: {type(e).__name__}: {str(e)}"}), 500

@app.post("/api/auth/login")
def api_login():
    try:
        data=request.json or {}
        email=(data.get("email") or "").strip().lower()
        password=(data.get("password") or "")
        rec=chroma_get_compat(users_col, {"email":{"$eq":email}}, include=["metadatas","ids"])
        ids=rec.get("ids",[])
        if not ids: return jsonify({"ok":False,"error":"Invalid email or password"}), 401
        meta=rec["metadatas"][0]
        if not check_password_hash(meta["password_hash"], password):
            return jsonify({"ok":False,"error":"Invalid email or password"}), 401
        uid=ids[0]; token=make_token(uid, email, role=meta.get("role","user"))
        return jsonify({"ok":True,"token":token,"user":{"id":uid,"email":email,"name":meta.get("name","")}})
    except Exception as e:
        return jsonify({"ok":False,"error":f"Server error: {e.__class__.__name__}: {e}"}), 500

@app.get("/api/auth/me")
@require_auth
def api_me():
    try:
        u=request.user
        rec=users_col.get(ids=[u["id"]], include=["metadatas"])
        meta=rec["metadatas"][0] if rec.get("metadatas") else {}
        return jsonify({"ok":True,"user":{"id":u["id"],"email":u["email"],"name":meta.get("name"),
                                          "theme":meta.get("theme","auto"),"lang":meta.get("lang","en"),
                                          "consent_scanning": bool(meta.get("consent_scanning"))}})
    except Exception as e:
        return jsonify({"ok":False,"error":f"Server error: {e.__class__.__name__}: {e}"}), 500

# ---------- Preferences & Consent ----------
@app.post("/api/user/prefs")
@require_auth
def api_prefs():
    data=request.get_json(force=True, silent=True) or {}
    theme=(data.get("theme") or "").strip()
    lang=(data.get("lang") or "").strip()
    ups={}
    if theme in {"dark","light","auto"}: ups["theme"]=theme
    if lang: ups["lang"]=lang
    if not ups: return jsonify({"ok":False,"error":"no changes"}), 400
    update_user_metadata(request.user["id"], ups)
    return jsonify({"ok":True})

@app.route("/api/consent", methods=["GET","POST"])
def api_consent():
    uid,_=try_parse_user()
    if request.method=="GET":
        if uid:
            return jsonify({"ok":True,"consent_scanning": has_scanning_consent_uid(uid)})
        return jsonify({"ok":True,"consent_scanning": request.cookies.get("consent_scanning","0")=="1"})
    data=request.get_json(force=True, silent=True) or {}
    val=bool(data.get("consent_scanning"))
    if uid:
        update_user_metadata(uid, {"consent_scanning": val, "consent_updated_at": datetime.datetime.utcnow().isoformat()})
        return jsonify({"ok":True,"consent_scanning": val})
    resp=make_response(jsonify({"ok":True,"consent_scanning": val}))
    resp.set_cookie("consent_scanning", "1" if val else "0", max_age=60*60*24*365, samesite="Lax")
    return resp

# ---------- Profile ----------
@app.get("/api/profile")
@require_auth
def api_profile_get():
    meta, _, _ = get_user_record(request.user["id"])
    out={"email": meta.get("email") or request.user.get("email"),
         "name": meta.get("name") or meta.get("display_name") or "",
         "display_name": meta.get("display_name") or "",
         "bio": meta.get("bio") or "", "profession": meta.get("profession") or "",
         "interests": meta.get("interests") or "", "phone": meta.get("phone") or "",
         "location": meta.get("location") or "", "member_since": meta.get("member_since") or "",
         "photo_url": meta.get("photo_url") or "", "created_at": meta.get("created_at") or "",
         "updated_at": meta.get("updated_at") or "", "theme":meta.get("theme","auto"),
         "lang":meta.get("lang","en"), "consent_scanning": bool(meta.get("consent_scanning"))}
    return jsonify({"ok":True,"profile":out})

@app.post("/api/profile")
@require_auth
def api_profile_save():
    data=request.get_json(force=True, silent=True) or {}
    ups={"display_name": (data.get("display_name") or "").strip(),
         "bio": (data.get("bio") or "").strip(), "profession": (data.get("profession") or "").strip(),
         "interests": (data.get("interests") or "").strip(), "phone": (data.get("phone") or "").strip(),
         "location": (data.get("location") or "").strip(), "member_since": (data.get("member_since") or "").strip(),
         "updated_at": datetime.datetime.utcnow().isoformat()}
    if ups["display_name"]: ups["name"]=ups["display_name"]
    update_user_metadata(request.user["id"], ups)
    return jsonify({"ok":True})

@app.post("/api/profile/photo")
@require_auth
def api_profile_photo():
    if "file" not in request.files: return jsonify({"ok":False,"error":"file required"}), 400
    f=request.files["file"]
    if not f or not f.filename: return jsonify({"ok":False,"error":"no file"}), 400
    ext=(f.filename.rsplit(".",1)[-1].lower() if "." in f.filename else "")
    if ext not in {"jpg","jpeg","png"}: return jsonify({"ok":False,"error":"image must be jpg/jpeg/png"}), 400
    filename=secure_filename(f"{request.user['id']}_avatar_{uuid.uuid4().hex[:8]}.{ext}")
    dest=Path(app.config["UPLOAD_FOLDER"])/filename; f.save(str(dest)); url=f"/uploads/{filename}"
    update_user_metadata(request.user["id"], {"photo_url":url,"updated_at":datetime.datetime.utcnow().isoformat()})
    return jsonify({"ok":True,"photo_url":url})




# ---------- Chat ----------
CYBER_KB={"ddos":"A DDoS ...","dos":"A DoS ...","virus":"A computer virus ...","malware":"Malware ...","ransomware":"Ransomware ...","phishing":"Phishing ..."}
def kb_answer(message:str)->Optional[str]:
    t=message.lower()
    for k,v in CYBER_KB.items():
        if k in t: return v
    return None
def ollama_answer(message:str, target_lang:Optional[str]=None)->Optional[str]:
    if ollama is None: return None
    for model in OLLAMA_MODELS:
        try:
            resp=ollama.chat(model=model,
                             messages=[{"role":"system","content": system_prompt_for(target_lang or detect_lang_simple(message))},
                                       {"role":"user","content":message}],
                             options={"temperature":0.2})
            msg=(resp.get("message") or {}).get("content")
            if msg: return msg.strip()
        except Exception: continue
    return None

@app.post("/api/chat/new")
@require_auth
def api_new_chat():
    try:
        chat_id=str(uuid.uuid4()); uid=request.user["id"]
        save_message(uid, chat_id, "assistant", CHAT_GREETING)
        add_title_message(uid, chat_id, datetime.datetime.utcnow().strftime("Chat %Y-%m-%d %H:%M"), source="auto", reason="default")
        return jsonify({"ok":True,"chat_id":chat_id})
    except Exception as e:
        return jsonify({"ok":False,"error":f"Server error: {e.__class__.__name__}: {e}"}), 500

@app.post("/api/chat/send")
@require_auth
def api_chat_send():
    try:
        data = request.json or {}
        chat_id = data.get("chat_id") or ""
        content = (data.get("message") or "").strip()

        # --- Dynamic safety gate (intent-aware) ---
        gate = llm_safety_gate(content)
        if gate.get("block"):
            lang = detect_lang_simple(content)
            safe_reply = "I don't have assistance with your questions."
            try:
                save_message(
                    request.user.get("id", ""),
                    chat_id,
                    "assistant",
                    safe_reply,
                    extra_meta={"lang": lang, "safety": gate}
                )
            except Exception:
                pass
            return jsonify({
                "ok": True,
                "reply": safe_reply,
                "lang": lang,
                "suggestions": [],
                "safety": gate
            })

        # --- Main logic ---
        if not chat_id or not content:
            return jsonify({"ok": False, "error": "chat_id and message are required"}), 400

        uid = request.user["id"]
        lang = detect_lang_simple(content)

        save_message(uid, chat_id, "user", content, extra_meta={"lang": lang})

        if count_user_messages(uid, chat_id) == 1:
            latest = get_latest_title(uid, chat_id)
            if latest.get("source") != "user":
                add_title_message(
                    uid,
                    chat_id,
                    make_title_from_text(content, 48),
                    source="auto",
                    reason="first_user_message"
                )

        reply = None
        if REQUIRE_OLLAMA and ollama is not None:
            reply = ollama_answer(content, target_lang=lang)

        reply = reply or kb_answer(content) or f"(demo reply) You said: {content}"

        save_message(uid, chat_id, "assistant", reply, extra_meta={"lang": lang})

        return jsonify({"ok": True, "reply": reply, "lang": lang})

    except Exception as e:
        return jsonify({
            "ok": False,
            "error": f"Server error: {e.__class__.__name__}: {e}"
        }), 500


def _fetch_all_user_messages(uid: str, limit: int = 10000):
    try:
        rec = chroma_get_compat(
            messages_col,
            {"$and": [{"user_id": {"$eq": uid}}]},
            include=["metadatas", "documents"],
            limit=limit
        )
        if (rec.get("metadatas") or rec.get("documents")):
            return rec
    except Exception:
        pass

    try:
        rec = messages_col.get(include=["metadatas", "documents"], limit=limit)
    except Exception:
        rec = messages_col.get(include=["metadatas", "documents"])

    metas = rec.get("metadatas", []) or []
    docs = rec.get("documents", []) or []
    keep_m, keep_d = [], []

    for m, d in zip(metas, docs):
        if isinstance(m, dict) and m.get("user_id") == uid:
            keep_m.append(m)
            keep_d.append(d)

    return {"metadatas": keep_m, "documents": keep_d, "ids": []}


@app.get("/api/chat/history")
@require_auth
def api_chat_history():
    try:
        uid=request.user["id"]; rec=_fetch_all_user_messages(uid, limit=10000); title_map=get_titles_map(uid)
        out={}
        metas=rec.get("metadatas",[]) or []; docs=rec.get("documents",[]) or []
        n=max(len(metas), len(docs))
        for i in range(n):
            meta=metas[i] if i<len(metas) else {}; doc=decrypt_if_needed(docs[i] if i<len(docs) else ""); cid=meta.get("chat_id")
            if not cid: continue
            ts=str(meta.get("ts","")); title=title_map.get(cid) or ""
            if cid not in out or ts>out[cid]["updated_at"]:
                out[cid]={"chat_id":cid,"title": title or (doc[:32]+("…" if len(doc)>32 else "")) or "Untitled Chat",
                          "preview": (doc or "")[:120], "updated_at": ts,"last_role": meta.get("role")}
        chats=sorted(out.values(), key=lambda x:x["updated_at"], reverse=True)
        return jsonify({"ok":True,"chats":chats})
    except Exception as e:
        return jsonify({"ok":False,"error":f"Server error: {e.__class__.__name__}: {e}"}), 500

@app.get("/api/chat/messages")
@require_auth
def api_chat_messages():
    try:
        uid=request.user["id"]; chat_id=request.args.get("chat_id","")
        if not chat_id: return jsonify({"ok":False,"error":"chat_id required"}), 400
        rec=chroma_get_compat(messages_col, {"user_id":{"$eq":uid},"chat_id":{"$eq":chat_id}}, include=["metadatas","documents"], limit=5000)
        metas=rec.get("metadatas",[]) or []; docs=rec.get("documents",[]) or []; ids=rec.get("ids",[]) or []
        if not metas and not docs:
            rec_all=_fetch_all_user_messages(uid, limit=10000); metas_all=rec_all.get("metadatas",[]); docs_all=rec_all.get("documents",[])
            metas,docs=[],[]
            for m,d in zip(metas_all, docs_all):
                if m.get("chat_id")==chat_id: metas.append(m); docs.append(d)
        n=max(len(metas), len(docs), len(ids)); items=[]
        for i in range(n):
            meta=metas[i] if i<len(metas) else {}; doc=decrypt_if_needed(docs[i] if i<len(docs) else ""); mid=ids[i] if i<len(ids) else f"{chat_id}:{i}"
            items.append({"id":mid,"role":meta.get("role"),"content":doc,"ts":meta.get("ts","")})
        items=[x for x in items if x.get("role")!="title"]; items.sort(key=lambda x:x.get("ts",""))
        return jsonify({"ok":True,"messages":items})
    except Exception as e:
        return jsonify({"ok":False,"error":f"Server error: {e.__class__.__name__}: {e}"}), 500

@app.post("/api/chat/rename")
@require_auth
def api_chat_rename():
    try:
        data=request.json or {}
        chat_id=(data.get("chat_id") or "").strip(); title=(data.get("title") or "").strip()
        if not chat_id or not title: return jsonify({"ok":False,"error":"chat_id and title are required"}), 400
        if len(title)>120: title=title[:120]
        add_title_message(request.user["id"], chat_id, title, source="user", reason="manual_rename")
        return jsonify({"ok":True,"chat_id":chat_id,"title":title})
    except Exception as e:
        return jsonify({"ok":False,"error":f"Server error: {e.__class__.__name__}: {e}"}), 500

@app.post("/api/chat/delete")
@require_auth
def api_chat_delete():
    try:
        data=request.json or {}; chat_id=(data.get("chat_id") or "").strip()
        if not chat_id: return jsonify({"ok":False,"error":"chat_id is required"}), 400
        uid=request.user["id"]; ids=fetch_message_ids_for_chat(uid, chat_id); deleted=0
        if ids: messages_col.delete(ids=ids); deleted=len(ids)
        return jsonify({"ok":True,"deleted_messages":deleted,"chat_id":chat_id})
    except Exception as e:
        return jsonify({"ok":False,"error":f"Server error: {e.__class__.__name__}: {e}"}), 500

# ---------- Scans & uploads (consent-aware) ----------
@app.route("/scan_url", methods=["POST"])
def scan_url_route():
    if not has_scanning_consent_request():
        return jsonify({"ok": False, "error": "Consent required for scanning. Use POST /api/consent to enable."}), 403

    data = request.get_json(force=True, silent=True) or {}
    url = normalize_url((data.get("url") or "").strip())
    session_id = data.get("session_id", str(time.time()))
    style = (data.get("style") or "explain").lower()           # "explain" | "compact"
    detail = (data.get("detail_level") or "normal").lower()    # "short" | "normal" | "deep"

    mal, total = vt_scan_url(url)  # your existing VT helper
    if mal is None:
        return jsonify({"ok": False, "error": "Scan failed or VirusTotal not configured.", "session_id": session_id})

    risk = _classify_risk(mal, total)
    status = "MALICIOUS ❌" if mal > 0 else "Clean ✅"
    paragraphs = _build_paragraphs(url, mal, total, risk["label"], risk["ratio"])

    if detail == "short":
        paragraphs = paragraphs[:3]
    elif detail == "deep":
        paragraphs.insert(3,
            "### Why engines might flag this\n"
            "Engines look at known bad IPs/domains, URL patterns (credential keywords), redirects, and historical abuse. "
            "Absence of detections today does not prove long-term safety."
        )

    response_text = f"{url} → {status} ({mal}/{total}), risk: {risk['label']}." if style == "compact" else "\n\n".join(paragraphs)

    return jsonify({
        "ok": True,
        "session_id": session_id,
        "status": status,
        "risk": risk["label"],
        "score": {"malicious": mal, "total": total, "ratio": round(risk["ratio"], 4)},
        "response": response_text,
        "paragraphs": paragraphs,
        "tips": [
            "Never enter passwords after clicking an email link; navigate to the site manually.",
            "Turn on multi-factor authentication (MFA) for all important accounts.",
            "Keep browser and OS patched; use reputable endpoint protection."
        ],
        "prompts": _suggest_prompts(url)
    })


# --------------------------- /upload route ---------------------------
@app.route("/upload", methods=["POST"])
def upload_file():
    if not has_scanning_consent_request():
        return jsonify({"ok":False,"error":"Consent required for scanning. Use POST /api/consent to enable."}), 403

    if "file" not in request.files:
        return jsonify({"ok":False,"error":"No file provided"}), 400
    f = request.files["file"]
    if not f or not f.filename:
        return jsonify({"ok":False,"error":"No file selected"}), 400
    if not allowed_file(f.filename):
        return jsonify({"ok":False,"error":"Unsupported file type"}), 400

    # Size + save
    try:
        f.stream.seek(0, os.SEEK_END); size = f.stream.tell(); f.stream.seek(0)
    except Exception:
        size = None
    if size and size > PER_FILE_MAX:
        return jsonify({"ok":False,"error":"Per-file size limit exceeded"}), 400

    filename = secure_filename(f.filename)
    path = UPLOAD_FOLDER / filename
    f.save(str(path))
    ext = file_ext(filename)  # your existing helper, returns lower-cased extension

    # Optional: quick ZIP bomb flag
    zip_flag = None
    if ext == "zip":
        try:
            with zipfile.ZipFile(str(path)) as z:
                total = sum(zi.file_size for zi in z.infolist())
                ratio = total / max(path.stat().st_size, 1)
                if ratio > 100.0 or total > 750*1024*1024:
                    zip_flag = "Archive looks suspicious (possible decompression bomb: extremely high expansion ratio)."
        except zipfile.BadZipFile:
            zip_flag = "Archive appears corrupted or malformed."

    # VirusTotal file scan (your existing helper)
    vt_mal, vt_total = vt_scan_file(path)
    risk = _classify_risk(vt_mal or 0, vt_total or 0) if vt_mal is not None else {"label":"Unknown","ratio":0.0}

    # ---------------- your requested structure starts here ----------------
    media_sentence = None
    paragraphs = None

    if ext in IMAGE_EXTS:
        # IMAGE: use your ensemble, then produce paragraph report based on % AI
        try:
            p, info = ensemble_ai_prob_for_image(path)
        except Exception as e:
            p, info = None, {"error": str(e)}
        models_used = _extract_models_used(info)
        media_sentence = (f"AI image analysis failed: {info.get('error','unknown error')}."
                          if p is None else f"This image is likely {'AI-generated' if p >= 0.5 else 'real'} ({int(round(p*100))}%). models used: {models_used}.")
        paragraphs = _build_image_paragraphs(
            filename=filename,
            size_bytes=(size or path.stat().st_size),
            p_ai=(0.5 if p is None else float(p)),
            models_used=models_used,
            info=(info or {}),
            vt_mal=vt_mal,
            vt_total=vt_total
        )

    elif ext in VIDEO_EXTS:
        # VIDEO: mirror structure, still produce paragraphs
        try:
            p, info = ensemble_ai_prob_for_video(path)
        except Exception as e:
            p, info = None, {"error": str(e)}
        models_used = _extract_models_used(info)
        media_sentence = (f"AI video analysis failed: {info.get('error','unknown error')}."
                          if p is None else f"This video is likely {'AI-generated' if p >= 0.5 else 'real'} ({int(round(p*100))}%). models used: {models_used}.")
        paragraphs = _build_video_paragraphs(
            filename=filename,
            size_bytes=(size or path.stat().st_size),
            p_ai=(None if p is None else float(p)),
            models_used=models_used,
            info=(info or {}),
            vt_mal=vt_mal,
            vt_total=vt_total
        )

    elif ext in {"mp3","wav"}:
        # AUDIO: simple heuristic paragraph via generic file builder + note
        try:
            with wave.open(str(path),'rb') as audio:
                sr = audio.getframerate(); n = audio.getnframes()
                duration = n/sr if sr else 0.0
                data = np.frombuffer(audio.readframes(n), dtype=np.int16)
                amp_std = float(np.std(data))
                zcr = float(np.sum(np.diff(np.sign(data)) != 0)) / max(duration, 1e-6)
                is_ai = amp_std < 1000 and zcr < 100
                media_sentence = ("This audio may be AI-generated (synthetic voice)."
                                  if is_ai else "This audio likely comes from a human speaker.")
        except Exception as e:
            media_sentence = f"Audio analysis failed: {e}"

    # If not image/video, or to provide a unified doc-style explanation, fall back to generic file paragraphs
    if paragraphs is None:
        paragraphs = _build_file_paragraphs(
            filename=filename,
            ext=ext,
            size_bytes=(size or path.stat().st_size),
            vt_mal=(vt_mal or 0) if vt_mal is not None else 0,
            vt_total=(vt_total or 0) if vt_total is not None else 0,
            risk_label=risk["label"],
            ratio=risk["ratio"],
            media_sentence=media_sentence,
            zip_flag=zip_flag
        )
    # ---------------- your requested structure ends here ----------------

    # Compact header for quick previews (unchanged)
    vt_line = ("VT: scan failed" if vt_mal is None
               else f"VT: {'MALICIOUS ❌' if vt_mal>0 else 'Clean ✅'} ({vt_mal}/{vt_total})")
    header = f"{filename} → {vt_line}"

    return jsonify({
        "ok": True,
        "response": "\n\n".join(paragraphs),
        "paragraphs": paragraphs,
        "score": {
            "malicious": (vt_mal or 0) if vt_mal is not None else None,
            "total": (vt_total or 0) if vt_total is not None else None,
            "ratio": round(risk["ratio"], 4) if vt_mal is not None else None,
            "risk": risk["label"]
        },
        "header": header
    })
# --------------------------------------------------------------------
    if not has_scanning_consent_request():
        return jsonify({"ok":False,"error":"Consent required for scanning. Use POST /api/consent to enable."}), 403

    if "file" not in request.files:
        return jsonify({"ok":False,"error":"No file provided"}), 400
    f = request.files["file"]
    if not f or not f.filename:
        return jsonify({"ok":False,"error":"No file selected"}), 400
    if not allowed_file(f.filename):
        return jsonify({"ok":False,"error":"Unsupported file type"}), 400

    # Size + save
    try:
        f.stream.seek(0, os.SEEK_END); size = f.stream.tell(); f.stream.seek(0)
    except Exception:
        size = None
    if size and size > PER_FILE_MAX:
        return jsonify({"ok":False,"error":"Per-file size limit exceeded"}), 400

    filename = secure_filename(f.filename)
    path = UPLOAD_FOLDER / filename
    f.save(str(path))
    ext = file_ext(filename)

    # Archive quick bomb/suspicion test
    zip_flag = None
    if ext == "zip":
        try:
            with zipfile.ZipFile(str(path)) as z:
                total = sum(zi.file_size for zi in z.infolist())
                ratio = total / max(path.stat().st_size, 1)
                if ratio > 100.0 or total > 750*1024*1024:
                    zip_flag = "Archive looks suspicious (possible decompression bomb: extremely high expansion ratio)."
        except zipfile.BadZipFile:
            zip_flag = "Archive appears corrupted or malformed."

    # VirusTotal
    vt_mal, vt_total = vt_scan_file(path)
    if vt_mal is None:
        # VT unavailable — still return typed guidance
        risk_label = "Unknown"
        ratio = 0.0
    else:
        r = _classify_risk(vt_mal, vt_total)
        risk_label, ratio = r["label"], r["ratio"]

    # Media AI analysis (optional paragraphs)
    media_sentence = None
    try:
        if ext in IMAGE_EXTS:
            p, info = ensemble_ai_prob_for_image(path)
            media_sentence = (f"AI image analysis failed: {info.get('error','unknown error')}."
                              if p is None else verdict_sentence_from_prob(p, "This image", info))
        elif ext in VIDEO_EXTS:
            p, info = ensemble_ai_prob_for_video(path)
            media_sentence = (f"AI video analysis failed: {info.get('error','unknown error')}."
                              if p is None else verdict_sentence_from_prob(p, "This video", info))
        elif ext in {"mp3","wav"}:
            try:
                with wave.open(str(path),'rb') as audio:
                    sr = audio.getframerate(); n = audio.getnframes()
                    duration = n/sr if sr else 0.0
                    data = np.frombuffer(audio.readframes(n), dtype=np.int16)
                    amp_std = float(np.std(data))
                    zcr = float(np.sum(np.diff(np.sign(data)) != 0)) / max(duration, 1e-6)
                    is_ai = amp_std < 1000 and zcr < 100
                    media_sentence = ("This audio may be AI-generated (synthetic voice)."
                                      if is_ai else "This audio likely comes from a human speaker.")
            except Exception as e:
                media_sentence = f"Audio analysis failed: {e}"
    except Exception as e:
        media_sentence = media_sentence or f"Media analysis encountered an error: {e}"

    # Build explanatory paragraphs
    paragraphs = _build_file_paragraphs(
        filename=filename,
        ext=ext,
        size_bytes=(size or path.stat().st_size),
        vt_mal=(vt_mal or 0) if vt_mal is not None else 0,
        vt_total=(vt_total or 0) if vt_total is not None else 0,
        risk_label=risk_label,
        ratio=ratio,
        media_sentence=media_sentence,
        zip_flag=zip_flag
    )

    # Compact header line (for quick preview)
    vt_line = ("VT: scan failed"
               if vt_mal is None else f"VT: {'MALICIOUS ❌' if vt_mal>0 else 'Clean ✅'} ({vt_mal}/{vt_total})")
    header = f"{filename} → {vt_line}"

    return jsonify({
        "ok": True,
        "response": "\n\n".join(paragraphs),   # backward compatible with your existing UI
        "paragraphs": paragraphs,              # preferred for your improved UI
        "score": {
            "malicious": (vt_mal or 0) if vt_mal is not None else None,
            "total": (vt_total or 0) if vt_total is not None else None,
            "ratio": round(ratio, 4) if vt_mal is not None else None,
            "risk": risk_label
        },
        "tips": [
            "Open files only from trusted sources; verify sender identity out-of-band.",
            "Keep Office macros disabled by default; avoid enabling external content.",
            "Use a sandbox/VM to inspect executables or scripts before running."
        ],
        "prompts": [
            f"Summarize what makes {filename} risky and propose a block rule for our email/web gateway.",
            "Create an incident note with file hash, source, detections, user impact, and actions taken.",
            "Give a checklist for safely opening Office/PDF files received via email.",
            "Draft a team warning about recent malicious attachments and how to report them."
        ],
        "header": header
    })
    if not has_scanning_consent_request():
        return jsonify({"ok":False,"error":"Consent required for scanning. Use POST /api/consent to enable."}), 403
    if "file" not in request.files: return jsonify({"ok":False,"error":"No file provided"}), 400
    f=request.files["file"]
    if not f or not f.filename: return jsonify({"ok":False,"error":"No file selected"}), 400
    if not allowed_file(f.filename): return jsonify({"ok":False,"error":"Unsupported file type"}), 400
    try:
        f.stream.seek(0, os.SEEK_END); size=f.stream.tell(); f.stream.seek(0)
    except Exception: size=None
    if size and size>PER_FILE_MAX: return jsonify({"ok":False,"error":"Per-file size limit exceeded"}), 400
    filename=secure_filename(f.filename); path=UPLOAD_FOLDER/filename; f.save(str(path)); ext=file_ext(filename)

    if ext=="zip":
        try:
            with zipfile.ZipFile(str(path)) as z:
                total=sum(zi.file_size for zi in z.infolist()); ratio=total/max(path.stat().st_size,1)
                if ratio>100.0 or total>750*1024*1024:
                    return jsonify({"ok":True,"response":f"{filename} → suspicious archive (possible zip bomb)."})
        except zipfile.BadZipFile:
            pass

    vt_mal, vt_total = vt_scan_file(path)
    vt_line = "VT: scan failed" if vt_mal is None else f"VT: {'MALICIOUS ❌' if vt_mal>0 else 'Clean ✅'} ({vt_mal}/{vt_total})"
    header=f"{filename} → {vt_line}"

    paragraph=None
    if ext in IMAGE_EXTS:
        p,info=ensemble_ai_prob_for_image(path); paragraph = (f"AI image analysis failed: {info.get('error','unknown error')}." if p is None else verdict_sentence_from_prob(p, "This image", info))
    elif ext in VIDEO_EXTS:
        p,info=ensemble_ai_prob_for_video(path); paragraph = (f"AI video analysis failed: {info.get('error','unknown error')}." if p is None else verdict_sentence_from_prob(p, "This video", info))
    elif ext in {"mp3","wav"}:
        try:
            with wave.open(str(path),'rb') as audio:
                sr=audio.getframerate(); n=audio.getnframes(); duration=n/sr if sr else 0.0
                data=np.frombuffer(audio.readframes(n), dtype=np.int16)
                amp_std=float(np.std(data)); zcr=float(np.sum(np.diff(np.sign(data)) != 0))/max(duration,1e-6)
                is_ai = amp_std<1000 and zcr<100
                paragraph=("This audio may be AI-generated (synthetic voice)." if is_ai else "This audio likely comes from a human speaker.")
        except Exception as e:
            paragraph=f"Audio analysis failed: {e}"

    final=header + ("\n\n"+paragraph if paragraph else "")
    return jsonify({"ok":True,"response":final})

# =======================================================================
# Threat Simulation API (existing) + UI-compatible shim
# =======================================================================
SIM_STORE: Dict[str, Dict[str,Any]] = {}

_INDICATORS = [
    "urgent_language","mismatched_domain","generic_greeting","typos",
    "shortened_url","replyto_mismatch","attachment_zip","qr_login",
    "password_request","payment_request"
]

def _rand_domain()->str:
    brands=["microsoft","google","apple","facebook","netflix","paypal","amazon","instagram","tiktok","discord"]
    tlds=[".com",".co",".support",".help",".top",".site",".link",".me",".io",".shop"]
    return random.choice(brands)+random.choice(tlds)

def _phishy_domain(real:str)->str:
    base=real.split(".")[0]
    swap=base.replace("o","0").replace("l","1").replace("a","@")
    suffix=random.choice(["-secure",".verify","-auth","-support","-login","-notice"])
    tld=random.choice([".com",".net",".co",".click",".info",".top"])
    return f"{swap}{suffix}{tld}"

def _make_phishing_scenario(level:str)->Dict[str,Any]:
    brand=_rand_domain()
    bad=_phishy_domain(brand)
    to="you@company.com"
    from_name=random.choice(["IT Support","Security Team","Account Notice","Billing"])
    subj=random.choice([
        "URGENT: Action required to keep your account",
        "Password expires today – verify now",
        "New sign-in detected – confirm it's you",
        "Invoice attached – payment required"
    ])
    greeting=random.choice(["Dear user,","Hello,","Hi there,","Dear valued customer,"])
    indicators=set(["mismatched_domain","urgent_language"])
    if "Invoice" in subj: indicators.add("payment_request")
    if "Password" in subj: indicators.add("password_request")
    use_short = random.random()<0.5
    short = f"https://bit.ly/{secrets.token_urlsafe(5)}" if use_short else f"https://{bad}/verify"
    if use_short: indicators.add("shortened_url")
    attach=None
    if random.random()<0.35:
        attach=f"invoice_{random.randint(1000,9999)}.zip"; indicators.add("attachment_zip")
    body = textwrap.dedent(f"""
      {greeting}

      Your {brand} account requires immediate attention. We noticed unusual activity and will suspend access
      unless you verify within 1 hour. Please {('download the attachment and open the invoice' if attach else 'click the verification link')}
      to regain full access.

      Verification link: {short}

      Reply-To: support@{bad}
      """).strip()

    scenario={
        "type":"phishing",
        "level":level,
        "from":f"{from_name} <no-reply@{bad}>",
        "to":to,
        "subject":subj,
        "text":body,
        "links":[{"display":"Verify account","href":short,"actual_domain":bad}],
        "attachment": attach,
        "indicators": sorted(list(indicators))
    }
    return scenario

def _grade(actions:List[str], indicators:List[str])->Dict[str,Any]:
    actions=set(a.lower() for a in actions)
    bad={"clicked_link","opened_attachment","submitted_credentials","enabled_macros","paid_invoice"}
    good={"report","hover_link","delete","ask_it","use_report_button"}
    score=50
    penalty=0; bonus=0
    for a in actions:
        if a in bad: penalty+=20
        if a in good: bonus+=10
    score = max(0, min(100, score - penalty + bonus))
    passed = (score>=70) and not (actions & {"clicked_link","submitted_credentials","paid_invoice"})
    feedback=[]
    if "hover_link" not in actions:
        feedback.append("Hover links to reveal the real destination.")
    if "report" not in actions:
        feedback.append("Use the report/abuse button or forward to security.")
    if "opened_attachment" in actions:
        feedback.append("Avoid opening unexpected attachments (especially .zip).")
    if "clicked_link" in actions:
        feedback.append("Never click verification links from suspicious emails.")
    if "password_request" in indicators:
        feedback.append("Legitimate services rarely ask to re-enter passwords via email.")
    return {"score":score,"passed":passed,"feedback":feedback}

def _log_sim(sim_id:str, event:str, payload:Dict[str,Any]):
    try:
        logs_col.add(ids=[f"{sim_id}:{event}:{uuid.uuid4().hex}"],
                     metadatas=[{"kind":"simulation","event":event,"ts":datetime.datetime.utcnow().isoformat()}],
                     documents=[json.dumps(payload)])
    except Exception:
        pass

@app.post("/api/simulate")
def simulate():
    """Create a phishing/threat scenario for practice."""
    data=request.get_json(force=True, silent=True) or {}
    sim_type=(data.get("type") or "phishing").lower()
    level=(data.get("level") or "easy").lower()
    if sim_type!="phishing":
        return jsonify({"ok":False,"error":"Only 'phishing' type is supported for now."}), 400
    scenario=_make_phishing_scenario(level)
    sim_id=uuid.uuid4().hex
    SIM_STORE[sim_id]={"scenario":scenario,"created_at":time.time()}
    _log_sim(sim_id, "created", {"scenario":scenario})
    return jsonify({"ok":True,"id":sim_id,"scenario":scenario})

@app.post("/api/simulate/grade")
def simulate_grade():
    """Grade the user actions against the generated scenario."""
    data=request.get_json(force=True, silent=True) or {}
    sim_id=(data.get("id") or "").strip()
    actions=list(data.get("actions") or [])
    it=SIM_STORE.get(sim_id)
    if not it: return jsonify({"ok":False,"error":"Unknown simulation id"}), 404
    scenario=it["scenario"]; indicators=scenario.get("indicators",[])
    result=_grade(actions, indicators)
    report={
        "id":sim_id,
        "scenario_type":scenario.get("type"),
        "level":scenario.get("level"),
        "indicators":indicators,
        "actions":actions,
        "result":result
    }
    _log_sim(sim_id, "graded", report)
    return jsonify({"ok":True, "report":report})

# ---------- UI shim: /api/threat/simulate (matches frontend expectation) ----------
@app.post("/api/threat/simulate")
def api_threat_simulate():
    """Compatibility endpoint expected by the frontend's Threat Simulator UI.
    Input JSON: { "text": "...", "chat_id": "..." }
    Output JSON: { "ok": True, "result": { "level": "low|medium|high", "risk": 0-100, "hits": [] }, "tips": [] }
    """
    data = request.get_json(force=True, silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"ok": False, "error": "text is required"}), 400

    hits = []
    low = text.lower()
    def hit(k):
        if k not in hits: hits.append(k)

    if "verify" in low or "confirm" in low: hit("urgent_language")
    if "password" in low: hit("password_request")
    if "invoice" in low or "payment" in low: hit("payment_request")
    if "bit.ly" in low or "tinyurl" in low or "shorturl" in low: hit("shortened_url")
    if "zip" in low: hit("attachment_zip")
    if "reply-to:" in low and "@" in low: hit("replyto_mismatch")
    if "http://" in low or "https://" in low: hit("link_present")

    base = 30
    score = base + 12*len(hits)
    score = max(0, min(100, score))
    if score >= 80: level = "high"
    elif score >= 60: level = "medium"
    else: level = "low"

    tips = []
    if "shortened_url" in hits or "link_present" in hits:
        tips.append("Hover links to see the real destination before clicking.")
    if "password_request" in hits:
        tips.append("Legitimate services don’t ask you to re-enter credentials via email.")
    if "attachment_zip" in hits:
        tips.append("Avoid opening unexpected zip attachments.")
    if "payment_request" in hits:
        tips.append("Verify invoices or payment demands through a trusted channel.")

    return jsonify({"ok": True, "result": {"level": level, "risk": score, "hits": hits}, "tips": tips or ["Stay cautious and report suspicious messages to IT."]})

# ---------- Export Chat (txt/csv/pdf) ----------
def _fetch_chat_items(uid:str, chat_id:str):
    try:
        rec = chroma_get_compat(messages_col, {"user_id":{"$eq":uid},"chat_id":{"$eq":chat_id}},
                                include=["metadatas","documents"], limit=5000)
        metas = rec.get("metadatas",[]) or []
        docs  = rec.get("documents",[]) or []
    except Exception:
        metas, docs = [], []
    items = []
    for m,d in zip(metas, docs):
        role = m.get("role")
        if role == "title":
            continue
        items.append({"role": role, "ts": m.get("ts",""), "text": decrypt_if_needed(d)})
    items.sort(key=lambda x: x["ts"])
    return items

@app.get("/api/chat/export")
@require_auth
def api_chat_export():
    uid = request.user["id"]
    chat_id = (request.args.get("chat_id") or "").strip()
    fmt = (request.args.get("format") or "txt").lower()
    if not chat_id:
        return jsonify({"ok": False, "error": "chat_id required"}), 400
    if fmt not in {"txt","csv","pdf"}:
        return jsonify({"ok": False, "error": "format must be txt|csv|pdf"}), 400

    items = _fetch_chat_items(uid, chat_id)
    if not items:
        return jsonify({"ok": False, "error": "No messages found for this chat"}), 404

    if fmt == "txt":
        out = io.StringIO()
        for it in items:
            who = "User" if it["role"]=="user" else "Assistant"
            out.write(f"[{it['ts']}] {who}:\n{it['text']}\n\n")
        data = out.getvalue().encode("utf-8")
        return send_file(io.BytesIO(data), mimetype="text/plain", as_attachment=True, download_name=f"chat_{chat_id}.txt")

    if fmt == "csv":
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["timestamp","role","text"])
        for it in items:
            w.writerow([it["ts"], it["role"], it["text"].replace("\n","\\n")])
        data = out.getvalue().encode("utf-8")
        return send_file(io.BytesIO(data), mimetype="text/csv", as_attachment=True, download_name=f"chat_{chat_id}.csv")

    # Minimal single-page PDF (no external deps)
    def _pdf_escape(s):
        return s.replace("\\","\\\\").replace("(","\\(").replace(")","\\)")
    lines = []
    for it in items:
        who = "User" if it["role"]=="user" else "Assistant"
        lines.append(f"[{it['ts']}] {who}: {it['text']}")
        lines.append("")
    wrapped = []
    for raw in lines:
        if not raw:
            wrapped.append("")
            continue
        while len(raw) > 95:
            wrapped.append(raw[:95]); raw = raw[95:]
        wrapped.append(raw)
    content_lines = []
    y = 760
    for ln in wrapped:
        content_lines.append(f"BT /F1 10 Tf 50 {y} Td ({_pdf_escape(ln)}) Tj ET")
        y -= 14
        if y < 40:
            content_lines.append(f"BT /F1 10 Tf 50 26 Td ({_pdf_escape('... (truncated)')}) Tj ET")
            break
    stream = ("\n".join(content_lines)).encode("utf-8")
    pdf = io.BytesIO()
    def w(x): pdf.write(x if isinstance(x,bytes) else x.encode("latin-1"))
    w("%PDF-1.4\n")
    xref = []
    def obj(n, body):
        xref.append(pdf.tell()); w(f"{n} 0 obj\n"); w(body); w("\nendobj\n")
    obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
    obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>")
    xref.append(pdf.tell()); w("4 0 obj\n<< /Length "); w(str(len(stream))); w(" >>\nstream\n"); pdf.write(stream); w("\nendstream\nendobj\n")
    obj(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    xref_pos = pdf.tell()
    w("xref\n0 6\n"); w("0000000000 65535 f \n")
    for pos in xref: w(f"{pos:010d} 00000 n \n")
    w("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n"); w(str(xref_pos)); w("\n%%EOF")
    pdf.seek(0)
    return send_file(pdf, mimetype="application/pdf", as_attachment=True, download_name=f"chat_{chat_id}.pdf")

# ---------- Dev inspector ----------
@app.get("/api/dev/stats")
def api_stats():
    try:
        ucount=len(users_col.get()["ids"]); mcount=len(messages_col.get()["ids"]); lcount=len(logs_col.get()["ids"])
    except Exception: ucount=mcount=lcount=0
    return jsonify({"ok":True,"users":ucount,"messages":mcount,"logs":lcount,"persist_dir":PERSIST_DIR})

if __name__=="__main__":
    port=int(os.getenv("PORT","8080"))
    app.run(host="0.0.0.0", port=port, debug=True)


# -------------------- Optional TTS endpoint (server-side) --------------------
# POST /api/tts  JSON: {"text":"Hello", "voice":"en-US", "rate": 180}
# Returns: audio/wav
@app.route("/api/tts", methods=["POST"])
def api_tts():
    try:
        data = request.get_json(silent=True) or {}
        text = (data.get("text") or "").strip()
        voice = (data.get("voice") or "en-US").strip()
        rate = int(data.get("rate") or 180)
        if not text:
            return jsonify({"ok": False, "error": "text is required"}), 400

        try:
            import pyttsx3
        except Exception as e:
            return jsonify({"ok": False, "error": "TTS engine not available on server", "details": str(e)}), 501

        engine = pyttsx3.init()
        # Apply voice if available
        try:
            voices = engine.getProperty("voices") or []
            chosen = None
            lower = voice.lower()
            for v in voices:
                if getattr(v, "languages", None):
                    langs = [str(x).lower() for x in v.languages]
                    if any(lower in l for l in langs):
                        chosen = v; break
                if lower in (getattr(v, "id", "") or "").lower() or lower in (getattr(v, "name", "") or "").lower():
                    chosen = v; break
            if chosen:
                engine.setProperty("voice", getattr(chosen, "id", getattr(chosen, "name", None)))
        except Exception:
            pass

        try:
            engine.setProperty("rate", rate)
        except Exception:
            pass

        # Render to an in-memory WAV file
        import tempfile, wave, contextlib
        tmp_wav = tempfile.NamedTemporaryFile(delete=False, suffix=".wav")
        tmp_name = tmp_wav.name
        tmp_wav.close()
        try:
            engine.save_to_file(text, tmp_name)
            engine.runAndWait()
            from flask import send_file
            return send_file(tmp_name, mimetype="audio/wav", as_attachment=False, download_name="tts.wav")
        finally:
            import os, time
            # Delay deletion slightly to ensure the response is sent
            try:
                os.unlink(tmp_name)
            except Exception:
                pass
    except Exception as e:
        return jsonify({"ok": False, "error": "TTS error", "details": str(e)}), 500
    