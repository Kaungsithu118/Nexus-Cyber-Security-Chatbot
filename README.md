# NexusBot: Cybersecurity AI Chatbot 🛡️🤖

[![MCF Competition](https://img.shields.io/badge/MCF%20Competition-Top%2010%20Finalist-blue)](https://www.myanmar.gov.mm/mcf)
[![APICTA 2025](https://img.shields.io/badge/APICTA-2025%20Nominee-green)](https://apicta.org)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3+-red.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **🏆 Award-Winning Project:** Top 10 Finalist in Myanmar Computer Federation (MCF) & Myanmar Computer Professional Association (MCPA) Cybersecurity Chatbot Competition 2025 | Nominee for APICTA Awards 2025 representing Myanmar

## 🎯 Overview

NexusBot is an AI-powered cybersecurity assistant designed to educate users about online threats while providing real-time detection capabilities. The system combines machine learning, natural language processing, and security APIs to create a comprehensive digital safety platform.

## ✨ Features

### 🔍 **Threat Detection**
- **URL Scanning** - Malware detection via VirusTotal API
- **File Analysis** - Virus scanning for .txt, .pdf, and other file types
- **Image Verification** - AI-generated content detection + virus scanning
- **Audio Inspection** - Malware detection in audio files

### 🌐 **Multilingual Support**
- Supports 8 languages: English, French, Traditional Chinese, Simplified Chinese, Burmese, Arabic, Hindi, Spanish
- Automatic language detection using `langdetect` and `transformers.`

### 🔒 **Privacy & Security**
- End-to-end encryption using PyJWT & cryptography
- Auto-deletion of chat history after 30 days
- GDPR-compliant design with user consent mechanisms
- Detailed FAQ on privacy laws and regulations

### 🎨 **User Experience**
- Responsive web interface with Light/Dark mode
- Voice command support
- Chat history export (TXT, CSV formats)
- User profile management

## 🏗️ Architecture
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ User Interface │────│ Flask Backend │────│ AI/ML Services │
│ (HTML/CSS/JS) │ │ (Python) │ │ (Ollama, HF) │
└─────────────────┘ └─────────────────┘ └─────────────────┘
│ │ │
│ │ │
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Nginx Proxy │────│ Security APIs │────│ ChromaDB Store │
│ (Load Balancer)│ │ (VirusTotal, Hive)│ │ (Chat History) │
└─────────────────┘ └─────────────────┘ └─────────────────┘





## 🛠️ Technology Stack

| Category | Technologies |
|----------|-------------|
| **Backend Framework** | Flask, Flask-CORS, Werkzeug |
| **AI/ML Engine** | PyTorch, Transformers, Sentence-Transformers, Accelerate |
| **Security** | PyJWT, cryptography |
| **Database** | ChromaDB (Vector Store) |
| **LLM Integration** | Ollama |
| **Networking** | requests, urllib3 |
| **Computer Vision** | OpenCV, Pillow |
| **Language Processing** | langdetect |
| **Web Server** | Nginx, Waitress |
| **Frontend** | HTML5, CSS3, JavaScript |
| **Deployment** | Microsoft Azure Cloud |
| **Monitoring** | Custom audit logs |

## 🚀 Installation & Setup

### Prerequisites
- Python 3.9+
- Ollama installed locally
- API keys for:
  - VirusTotal
  - Hugging Face (optional)
  - Hive/Sightengine (optional)

### Installation Steps
```bash
# Clone repository
git clone https://github.com/Kaungsithu118/Nexus-Cyber-Security-Chatbot.git
cd Nexus-Cyber-Security-Chatbot

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys

# Run the application
python app.py

```

##📁 Project Structure

```bash
nexusbot/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── config/
│   ├── __init__.py
│   └── settings.py       # Configuration settings
├── modules/
│   ├── auth/             # Authentication module
│   ├── chat/             # Chat functionality
│   ├── scanner/          # Threat scanning modules
│   ├── nlp/              # Multilingual processing
│   └── utils/            # Utility functions
├── templates/            # HTML templates
├── static/               # CSS, JS, images
├── tests/                # Unit tests
└── docs/                 # Documentation
```


## 👥 Team Members

| Role | Member |
|------|--------|
| Project Lead & Frontend Developer | Ei Thandar Phyu |
| AI/ML Engineer,  Backend Developer & Security Specialist | Kaung Si Thu |
| Frontend Developer & UI/UX Designer | Aung Kaung Myat |
| Quality Assurance & Testing | Arker Min Myat |
| Documentation & Research | Zawe Thuta |

🔧 API Integration Details
Security APIs Used:
VirusTotal - Malware detection for URLs and files

Hugging Face - AI-generated content detection

Hive/Sightengine - Additional media analysis

AIORNOT - AI content verification

Custom AI Models:
Fine-tuned Transformer models for Burmese language support

Sentence embedding models for semantic search

Custom threat classification models

📊 Performance & Results
Key Metrics:
Accuracy: 92% on known malware detection

Response Time: < 3 seconds for most queries

Language Support: 8 languages with >85% accuracy

Scalability: Tested with 100+ concurrent users

Competition Achievements:
🏆 Myanmar Computer Federation (MCF) & MCPA Cybersecurity Chatbot Competition 2025: Top 10 Finalist

🎯 APICTA Awards 2025: Official Nominee representing Myanmar

🌐 Live Deployment: Successfully hosted on Microsoft Azure


📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

🤝 Contributing
Contributions are welcome! Please read our Contributing Guidelines for details.

🙏 Acknowledgments
Myanmar Computer Federation & Myanmar Computer Professional Association for the APYPS competition platform

APICTA Awards for the nomination opportunity

Open-source community for the amazing tools and libraries

Our mentors and advisors for their guidance


