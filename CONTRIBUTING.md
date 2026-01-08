# Contributing to NexusBot 🛡️🤖

First off, thank you for considering contributing to NexusBot! It's people like you who make open source such an amazing community. ✨

As an award-winning project (**Top 10 Finalist in MCF/MCPA Competition 2025** and **APICTA 2025 Nominee**), we welcome contributions from developers, cybersecurity enthusiasts, and AI researchers alike.

## 📜 Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## 🚀 Getting Started

### Prerequisites
- Python 3.9 or higher
- Git
- Ollama (for local LLM testing)
- API keys for external services (optional for development)

### Setting Up Development Environment

1. **Fork the Repository**
   ```bash
   # Click the 'Fork' button on GitHub
   # Clone your fork locally
   git clone https://github.com/your-username/Nexus-Cyber-Security-Chatbot.git
   cd Nexus-Cyber-Security-Chatbot
   ```
2. **Set Up Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. **Install Dependencies**
  ```bash
  pip install -r requirements.txt
  pip install -r requirements-dev.txt  # Development dependencies
  ```
4. **Configure Environment**
  ```bash
  cp .env.example .env
  # Edit .env with your configuration
  ```
5. **Run the Application**
  ```bash
  python app.py
  ```
