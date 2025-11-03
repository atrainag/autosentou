# Autosentou - Automated Penetration Testing Platform

Autosentou is an intelligent, AI-powered automated penetration testing platform that streamlines security assessments and generates comprehensive security reports. It combines traditional penetration testing tools with modern AI/RAG capabilities to provide enhanced vulnerability analysis and remediation recommendations.

## Features

### Core Capabilities

- **Automated Vulnerability Scanning**: End-to-end penetration testing workflow with multiple specialized phases
- **AI-Powered Analysis**: Integration with AI for intelligent vulnerability categorization
- **RAG-Enhanced Knowledge Base**: Semantic search and matching of vulnerabilities to curated security knowledge
- **Comprehensive Reporting**: Automated generation of professional reports in PDF, DOCX, and HTML formats
- **Exploit Intelligence**: Automated searching across ExploitDB, GitHub, and Google for relevant exploits

### Testing Phases

1. **Information Gathering**
   - Network scanning and service enumeration
   - Port detection and service version identification
   - Technology stack fingerprinting

2. **Web Enumeration**
   - Directory and file discovery (feroxbuster, gospider)
   - API endpoint identification
   - Admin panel detection
   - Sensitive file exposure analysis
   - Path vulnerability categorization 

3. **Vulnerability Analysis**
   - CVE lookup and matching
   - AI-powered vulnerability categorization
   - Severity assessment
   - RAG-based remediation suggestions

4. **SQL Injection Testing**
   - Automated SQLi detection and exploitation
   - Multiple injection technique support
   - Database fingerprinting

5. **Authentication Testing**
   - Login form detection
   - Credential brute-forcing
   - Authentication bypass attempts

6. **Report Generation**
   - Executive summaries
   - Detailed vulnerability findings
   - Technical recommendations
   - Appendices with tool outputs
   - CWE/CVE enrichment from knowledge base

## Architecture

### Backend (FastAPI)

```
autosentou-backend/
├── controllers/          # API route handlers
│   ├── jobs_controller.py
│   └── knowledge_base_controller.py
├── services/
│   ├── phases/          # Testing phase implementations
│   │   ├── info_gathering.py
│   │   ├── web_enumeration.py
│   │   ├── vulnerability_analysis.py
│   │   ├── sqli_testing.py
│   │   ├── authentication_testing.py
│   │   └── report_generation/
│   ├── ai/              # AI and RAG services
│   │   ├── config.py
│   │   ├── rag_service.py
│   │   ├── knowledge_manager.py
│   │   └── vulnerability_categorizer.py
│   ├── exploit_search/  # Exploit intelligence
│   │   ├── exploitdb_searcher.py
│   │   ├── github_searcher.py
│   │   └── google_searcher.py
│   ├── poc_execution/   # Proof-of-concept execution
│   └── utils/           # Helper utilities
├── models.py            # SQLAlchemy database models
├── database.py          # Database configuration
└── main.py             # Application entry point
```

### Frontend (Vue.js)

```
autosentou-frontend/
├── src/
│   ├── components/
│   │   ├── dashboard/
│   │   ├── job-detail/
│   │   ├── knowledge-base/
│   │   ├── wordlist/
│   │   └── common/
│   ├── views/
│   │   ├── Dashboard.vue
│   │   ├── ScanCreate.vue
│   │   ├── JobsList.vue
│   │   ├── JobDetail.vue
│   │   ├── ReportViewer.vue
│   │   ├── ReportDashboard.vue
│   │   ├── KnowledgeBaseManager.vue
│   │   └── WordlistManager.vue
│   ├── stores/          # Pinia state management
│   ├── services/        # API integration
│   └── router/          # Vue Router configuration
└── package.json
```

## Technology Stack

### Backend
- **Framework**: FastAPI
- **Database**: SQLAlchemy (SQLite)
- **AI/ML**:
  - Google Gemini
  - OpenAI
  - Sentence Transformers
  - ChromaDB (Vector Database)
  - LangChain
- **Document Processing**:
  - WeasyPrint (PDF)
  - python-docx (Word)
  - markdown2
- **Security Tools**:
  - nmap
  - sqlmap
  - feroxbuster
  - gospider
  - hydra

### Frontend
- **Framework**: Vue.js 3
- **State Management**: Pinia
- **Routing**: Vue Router
- **Styling**: Tailwind CSS
- **UI Components**:
  - Headless UI
  - Heroicons
- **Charts**: Chart.js + vue-chartjs
- **HTTP Client**: Axios

## Prerequisites

### System Requirements

- Python 3.12+
- Node.js 16+
- npm or yarn

### Required Tools

The following penetration testing tools must be installed on your system:

- `nmap` - Network scanner
- `sqlmap` - SQL injection tool
- `feroxbuster` - Web content discovery
- `gospider` - Web spider

### API Keys

Configure the following API keys in your environment:

- Google Gemini API key (for AI analysis)
- OpenAI API key (optional, for alternative AI provider)

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd autosentou
```

### 2. Backend Setup

```bash
cd autosentou-backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install

# Configure environment variables
# Create a .env file with your API keys:
# GOOGLE_API_KEY=your_gemini_api_key
# OPENAI_API_KEY=your_openai_api_key (optional)
```

### 3. Frontend Setup

```bash
cd autosentou-frontend

# Install dependencies
npm install

# Configure API endpoint (if needed)
# Update src/services/api.js with your backend URL
```

## Usage

### Starting the Backend

```bash
cd autosentou-backend
source venv/bin/activate # Or activate your conda environment
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`
- API Documentation: `http://localhost:8000/docs`
- Alternative Docs: `http://localhost:8000/redoc`

### Starting the Frontend

```bash
cd autosentou-frontend
npm install
npm run dev
```

The web interface will be available at `http://localhost:5173`

### Running a Scan

1. Navigate to the dashboard
2. Click "New Scan" or go to the Scan Create page
3. Enter target information:
   - Target URL or IP address
   - Scan description
   - Optional: Custom wordlist
4. Click "Start Scan"
5. Monitor progress in real-time on the Job Detail page
6. View and download reports when the scan completes

## API Endpoints

### Jobs

- `GET /jobs` - List all jobs
- `POST /jobs` - Create a new scan job
- `GET /jobs/{job_id}` - Get job details
- `DELETE /jobs/{job_id}` - Delete a job
- `GET /jobs/{job_id}/report` - Get job report

### Knowledge Base

- `GET /knowledge-base/vulnerabilities` - List all KB vulnerabilities
- `POST /knowledge-base/vulnerabilities` - Add a vulnerability to KB
- `PUT /knowledge-base/vulnerabilities/{id}` - Update KB entry
- `DELETE /knowledge-base/vulnerabilities/{id}` - Delete KB entry
- `POST /knowledge-base/populate-findings` - Auto-populate KB from findings

### Reports

- `GET /jobs/{job_id}/report/pdf` - Download PDF report
- `GET /jobs/{job_id}/report/docx` - Download DOCX report
- `GET /jobs/{job_id}/report/html` - Download HTML report

## Knowledge Base System

The Knowledge Base allows you to:

- Store curated vulnerability information with CWE mappings
- Link discovered findings to KB entries using RAG similarity matching
- Enrich reports with standardized remediation advice
- Build organizational security knowledge over time

See [REPORT_GENERATION_DETAIL.md](REPORT_GENERATION_DETAIL.md) for more information on how KB enrichment works.

## AI/RAG Integration

Autosentou uses RAG (Retrieval-Augmented Generation) to enhance vulnerability analysis:

1. **Vulnerability Categorization**: AI categorizes findings into logical groups
2. **Semantic Matching**: ChromaDB performs vector similarity matching between findings and KB entries
3. **Remediation Generation**: LangChain generates contextual remediation advice
4. **Report Enhancement**: AI-generated summaries and technical details

## Workflow Diagrams

- [Path and Auth Analyzers](ANALYZERS_DETAIL.md)
- [Report Generation Process](REPORT_GENERATION_DETAIL.md)

## Database Schema

The platform uses SQLite with the following main models:

- **Job**: Scan job information and status
- **Phase**: Individual testing phase records
- **Finding**: Discovered vulnerabilities and issues
- **Report**: Generated report metadata
- **KnowledgeBaseVulnerability**: Curated security knowledge
- **Wordlist**: Custom wordlist management

## Configuration

You need .env file on `autosentou-backend/.env`, below is an example
```
# Tool paths
NMAP_PATH=/usr/bin/nmap
DIRSEARCH_PATH=/usr/local/bin/dirsearch
HYDRA_PATH=/usr/bin/hydra
MEDUSA_PATH=/usr/bin/medusa
SQLMAP_PATH=/usr/bin/sqlmap
PANDOC_PATH=/usr/bin/pandoc

# Wordlists
DIRSEARCH_WORDLIST=/usr/share/wordlists/dirb/common.txt
HYDRA_USERNAME_LIST=/usr/share/wordlists/rockyou.txt
HYDRA_PASSWORD_LIST=/usr/share/wordlists/rockyou.txt
MEDUSA_USERNAME_LIST=/usr/share/wordlists/rockyou.txt
MEDUSA_PASSWORD_LIST=/usr/share/wordlists/rockyou.txt

# AI Provider Configuration
# Options: gemini, openai, deepseek, ollama
AI_PROVIDER=gemini

# API Keys
GEMINI_API_KEY=your_gemini_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
DEEPSEEK_API_KEY=your_deepseek_api_key_here

# Ollama Configuration (for local models)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3

# Embedding Model
EMBEDDING_MODEL=BAAI/bge-large-en-v1.5

# ChromaDB Configuration
CHROMA_PERSIST_DIR=./chroma_db
CHROMA_COLLECTION=pentest_vulns

# AI Model Parameters
AI_TEMPERATURE=0.7
AI_MAX_TOKENS=2000

# Browser Configuration
BROWSER_HEADLESS=true
BROWSER_TIMEOUT=30000

# Database
DATABASE_URL=sqlite:///./pentest.db

# Security
SECRET_KEY=your-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

## Security Considerations

**IMPORTANT**: This tool is designed for authorized security testing only.

- Only use on systems you own or have explicit permission to test
- Respect scope limitations and rules of engagement
- Follow responsible disclosure practices
- Be aware of local laws and regulations regarding security testing
