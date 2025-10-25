# Automated Penetration Testing Report Generator

A comprehensive automated penetration testing tool that performs network reconnaissance, vulnerability analysis, web enumeration, SQL injection testing, brute force attacks, and generates detailed reports.

## Features

### Core Pentesting Phases

1. **Information Gathering**

   - Nmap port scanning with service detection
   - WHOIS lookups for domain information
   - DNS enumeration using dnsenum
   - Network topology discovery

2. **Vulnerability Analysis**

   - CVE database integration for service vulnerabilities
   - Proof of Concept (PoC) execution
   - CVSS scoring and risk assessment
   - Exploit difficulty analysis

3. **Web Enumeration**

   - Directory and file discovery using dirsearch
   - AI-powered analysis of discovered paths
   - Risk assessment of web endpoints
   - Pattern matching for sensitive directories

4. **SQL Injection Testing**

   - Automated SQLMap integration
   - Multiple endpoint testing (up to 3 as requested)
   - Injection type detection
   - Database fingerprinting

5. **Brute Force Testing**

   - Hydra and Medusa integration
   - Login endpoint discovery
   - Credential brute forcing
   - Success/failure tracking

6. **Report Generation**
   - Comprehensive markdown reports
   - PDF conversion using Pandoc
   - Executive summary with key findings
   - Detailed technical analysis

## Project Structure

```
autosentou/
├── main.py                          # FastAPI application entry point
├── models.py                        # Database models and Pydantic schemas
├── database.py                      # Database configuration
├── controllers/
│   └── jobs_controller.py          # API endpoints for scan management
├── services/
│   ├── jobs_service.py             # Main scan orchestration
│   ├── config.py                   # Configuration management
│   ├── utils/
│   │   ├── helpers.py              # Data conversion utilities
│   │   └── system.py               # System command execution
│   └── phases/
│       ├── info_gathering.py       # Network reconnaissance
│       ├── vulnerability_analysis.py # CVE analysis and PoC execution
│       ├── web_enumeration.py      # Web directory discovery
│       ├── sqli_testing.py         # SQL injection testing
│       ├── brute_force_testing.py  # Login brute forcing
│       └── report_generation.py    # Report creation
└── reports/                        # Generated reports directory
```

## Installation

### Prerequisites

- Python 3.8+
- Required tools (install via package manager):
  - nmap
  - dirsearch
  - hydra
  - medusa
  - sqlmap
  - pandoc
  - dnsenum
  - whois

### Setup

1. Clone the repository:

```bash
git clone <repository-url>
cd autosentou
```

2. Install Python dependencies:

```bash
pip install -r requirements.txt
```

3. Install required tools:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install nmap hydra medusa sqlmap pandoc dnsutils whois

# Install dirsearch
git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch
sudo ln -s /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch
```

4. Run the application:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## API Usage

### Start a Scan

```bash
curl -X POST "http://localhost:8000/api/start-scan" \
     -H "Content-Type: application/json" \
     -d '{
       "target": "192.168.1.100",
       "description": "Internal network scan",
       "scan_type": "comprehensive",
       "include_brute_force": true,
       "include_sqli_testing": true,
       "include_web_enumeration": true,
       "max_threads": 10,
       "timeout": 300
     }'
```

### Check Scan Status

```bash
curl "http://localhost:8000/api/scan-status/{job_id}"
```

### List All Scans

```bash
curl "http://localhost:8000/api/scans"
```

### Check Tool Status

```bash
curl "http://localhost:8000/api/tools/status"
```

## Configuration

### Scan Types

- **comprehensive**: Full pentesting suite (default)
- **quick**: Basic network scan only
- **web_only**: Web-focused testing
- **network_only**: Network reconnaissance only

### Environment Variables

```bash
# Tool paths
export NMAP_PATH="/usr/bin/nmap"
export DIRSEARCH_PATH="/usr/local/bin/dirsearch"
export HYDRA_PATH="/usr/bin/hydra"
export MEDUSA_PATH="/usr/bin/medusa"
export SQLMAP_PATH="/usr/bin/sqlmap"
export PANDOC_PATH="/usr/bin/pandoc"

# Wordlists
export DIRSEARCH_WORDLIST="/usr/share/wordlists/dirb/common.txt"
export HYDRA_USERNAME_LIST="/usr/share/wordlists/rockyou.txt"
export HYDRA_PASSWORD_LIST="/usr/share/wordlists/rockyou.txt"
```

## Report Generation

Reports are automatically generated in the `reports/{job_id}/` directory:

- `report_{job_id}.md` - Markdown format
- `report_{job_id}.pdf` - PDF format (if Pandoc is available)

### Report Sections

1. **Executive Summary** - High-level findings and recommendations
2. **Information Gathering** - Network scan results and service discovery
3. **Vulnerability Analysis** - CVE analysis and PoC results
4. **Web Enumeration** - Directory discovery and AI analysis
5. **SQL Injection Testing** - Vulnerable endpoints and payloads
6. **Brute Force Testing** - Successful login attempts
7. **Recommendations** - Security improvement suggestions

## Security Considerations

- **Target Validation**: Input validation for scan targets
- **Rate Limiting**: Configurable timeouts and thread limits
- **Safe Testing**: Non-destructive PoC execution
- **Logging**: Comprehensive audit trail
- **Error Handling**: Graceful failure handling

## Development

### Adding New Phases

1. Create a new phase file in `services/phases/`
2. Implement the phase function following the existing pattern
3. Add the phase to the scan workflow in `jobs_service.py`
4. Update the report generation to include new findings

### Custom Tools Integration

1. Add tool configuration to `services/config.py`
2. Implement tool wrapper in appropriate phase file
3. Add tool validation to `ConfigManager.validate_tools()`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for authorized penetration testing and security research only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.
