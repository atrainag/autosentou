# Autosentou - Automated Penetration Testing Platform

Autosentou is an intelligent, AI-powered automated penetration testing platform that streamlines security assessments and generates comprehensive security reports. It combines traditional penetration testing tools with modern AI/RAG capabilities to provide enhanced vulnerability analysis and remediation recommendations.

## Demo

[![Autosentou Demo](https://img.youtube.com/vi/piLfAfjIgPg/maxresdefault.jpg)](https://www.youtube.com/watch?v=piLfAfjIgPg)

## Features

### Core Capabilities

- **Automated Vulnerability Scanning**: End-to-end penetration testing workflow with multiple specialized phases.
- **AI-Powered Analysis**: Integration with Gemini, OpenAI, DeepSeek, or Ollama for intelligent vulnerability categorization.
- **RAG-Enhanced Knowledge Base**: Semantic search and matching of vulnerabilities to curated security knowledge using ChromaDB.
- **Comprehensive Reporting**: Automated generation of professional reports in PDF, DOCX, and HTML formats.
- **Exploit Intelligence**: Automated searching across ExploitDB, GitHub, and Google for relevant exploits.
- **Smart Web Enumeration**: Intelligent path analysis and attack surface mapping.

### Testing Phases

1. **Information Gathering**:
   - Network scanning with **Nmap** (SYN scan, service version detection).
   - Port detection and technology stack fingerprinting.

2. **Web Enumeration**:
   - Directory and file discovery (supports **Dirsearch**, **Feroxbuster**, **Gospider**).
   - Intelligent path analysis and RAG-based categorization.
   - Auth endpoint detection.

3. **Vulnerability Analysis**:
   - CVE lookup and matching.
   - AI-driven severity assessment and remediation suggestions.

4. **SQL Injection Testing**:
   - Automated detection and exploitation using **SQLMap**.
   - Support for various injection techniques and database fingerprinting.

5. **Authentication Testing**:
   - Credential brute-forcing using **Hydra** and **Medusa**.
   - Login form detection and bypass attempts.

6. **Report Generation**:
   - Executive summaries and detailed technical findings.
   - Context-aware recommendations powered by AI.

## Architecture

### Backend

- **Framework**: FastAPI (Python)
- **Database**: SQLite (with SQLAlchemy)
- **AI/ML**: LangChain, ChromaDB, Sentence Transformers
- **Browser Automation**: Playwright
- **Document Processing**: WeasyPrint, Python-docx, Pandoc

### Frontend

- **Framework**: Vue 3 + Vite
- **State Management**: Pinia
- **UI Framework**: Tailwind CSS, Headless UI
- **Visualization**: Chart.js

## Prerequisites

### System Requirements

- **Python**: 3.10+
- **Node.js**: 16+
- **OS**: Linux (Kali Linux recommended) or Windows (with tools installed)

### Required Tools

Ensure the following tools are installed and accessible in your system PATH:

- `nmap`
- `sqlmap`
- `hydra`
- `medusa`
- `pandoc`
- `dirsearch` (or equivalent web fuzzer)

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd autosentou
```

### 2. Backend Setup

```bash
cd autosentou-backend

# Create and activate virtual environment
python -m venv venv
# Linux/Mac
source venv/bin/activate
# Windows
# venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install

# Create .env file
cp .env.example .env  # You'll need to create this or edit .env manually
```

### 3. Frontend Setup

```bash
cd autosentou-frontend

# Install dependencies
npm install
```

## Configuration

Create a `.env` file in `autosentou-backend/` with the following configuration. Adjust paths to match your system.

```ini
# Tool paths (Adjust if tools are not in system PATH)
NMAP_PATH=nmap
DIRSEARCH_PATH=dirsearch
HYDRA_PATH=hydra
MEDUSA_PATH=medusa
SQLMAP_PATH=sqlmap
PANDOC_PATH=pandoc

# Wordlists
DIRSEARCH_WORDLIST=/usr/share/wordlists/dirb/common.txt
HYDRA_USERNAME_LIST=/usr/share/wordlists/rockyou.txt
HYDRA_PASSWORD_LIST=/usr/share/wordlists/rockyou.txt
MEDUSA_USERNAME_LIST=/usr/share/wordlists/rockyou.txt
MEDUSA_PASSWORD_LIST=/usr/share/wordlists/rockyou.txt

# AI Provider Configuration
# Options: gemini, openai, deepseek, ollama
AI_PROVIDER=gemini

# API Keys (Fill required keys)
GEMINI_API_KEY=your_gemini_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
DEEPSEEK_API_KEY=your_deepseek_api_key_here

# Ollama Configuration (for local models)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3

# Vector DB
CHROMA_PERSIST_DIR=./chroma_db
CHROMA_COLLECTION=pentest_vulns

# App Settings
SECRET_KEY=your_super_secret_key
ALGORITHM=HS256
```

## Usage

### 1. Start the Backend

```bash
cd autosentou-backend
# Ensure venv is active
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`. Documentation: `http://localhost:8000/docs`.

### 2. Start the Frontend

```bash
cd autosentou-frontend
npm run dev
```

Access the dashboard at `http://localhost:5173`.

### 3. Run a Scan

1.  Open the web dashboard.
2.  Navigate to **"New Scan"**.
3.  Enter the **Target URL**.
4.  Select scan options (Phases, AI Provider).
5.  Click **"Start Scan"**.
6.  Monitor progress in the **Job Detail** view.

## Disclaimer

**IMPORTANT**: This tool is designed for **authorized security testing only**.

- Only use on systems you own or have explicit written permission to test.
- Misuse of this tool may violate local, state, or federal laws.
- The authors are not responsible for any damage caused by the misuse of this software.

