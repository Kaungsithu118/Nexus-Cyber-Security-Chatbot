# NexusBot: Cybersecurity AI Chatbot 🛡️🤖

[![APYPS Finalist](https://img.shields.io/badge/APYPS-Top%2010%20Finalist-blue)](https://apyps.org)
[![APICTA 2025](https://img.shields.io/badge/APICTA-2025%20Nominee-green)](https://apicta.org)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3+-red.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **🏆 Award-Winning Project:** Top 10 Finalist in APYPS Cybersecurity Chatbot Competition 2025 | Nominee for APICTA Awards 2025 representing Myanmar

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
- Automatic language detection using `langdetect` and `transformers`

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
