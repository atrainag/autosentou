"""
Appendix Generation

Generates appendix sections including tools, OWASP reference, and raw outputs info.
"""

from typing import Dict, Any
from datetime import datetime


def generate_appendix_section(phases_data: Dict[str, Any]) -> str:
    """
    Generate complete appendix section.
    """
    lines = []
    
    # Appendix A: Tools and Versions
    lines.append(generate_tools_appendix())
    lines.append("\n")
    
    # Appendix B: OWASP TOP 10 Reference
    lines.append(generate_owasp_reference())
    lines.append("\n")
    
    # Appendix C: Methodology Details
    lines.append(generate_methodology_details())
    
    return ''.join(lines)


def generate_tools_appendix() -> str:
    """
    Generate Appendix A: Tools and Versions.
    """
    lines = []
    lines.append("### Tools and Versions\n\n")
    lines.append("The following tools were used during this penetration testing assessment:\n\n")
    
    # Tools table
    lines.append("| Tool | Version | Purpose | Official Website |\n")
    lines.append("|------|---------|---------|------------------|\n")
    lines.append("| Nmap | 7.94+ | Network scanning and service detection | https://nmap.org |\n")
    lines.append("| Dirsearch | 0.4.3+ | Web directory and file enumeration | https://github.com/maurosoria/dirsearch |\n")
    lines.append("| SQLMap | 1.8+ | Automated SQL injection testing | https://sqlmap.org |\n")
    lines.append("| Hydra | 9.5+ | Network authentication brute forcing | https://github.com/vanhauser-thc/thc-hydra |\n")
    lines.append("| Playwright | Latest | Browser automation for web analysis | https://playwright.dev |\n")
    lines.append("| Python | 3.11+ | Scripting and automation | https://python.org |\n")
    lines.append("| AI Assistant | Claude Sonnet 4.5 | Vulnerability analysis and reporting | https://anthropic.com |\n")
    
    lines.append("\n**Note**: All tools were used with default or conservative settings to minimize disruption to target systems.\n\n")
    lines.append("**Raw Output Files**: All detailed tool outputs, logs, and evidence are available in the `{target}_raw_outputs.zip` file accompanying this report.\n\n")
    
    return ''.join(lines)


def generate_owasp_reference() -> str:
    """
    Generate Appendix B: OWASP TOP 10 2021 Complete Reference.
    """
    lines = []
    lines.append("### OWASP TOP 10 2021 Reference\n\n")
    lines.append("The OWASP TOP 10 is a standard awareness document for developers and web application security. ")
    lines.append("It represents a broad consensus about the most critical security risks to web applications.\n\n")
    
    # Complete OWASP TOP 10 table
    lines.append("| Category | Name | Description |\n")
    lines.append("|----------|------|-------------|\n")
    lines.append("| A01:2021 | Broken Access Control | Failures related to access control allowing unauthorized access |\n")
    lines.append("| A02:2021 | Cryptographic Failures | Failures related to cryptography leading to data exposure |\n")
    lines.append("| A03:2021 | Injection | User-supplied data is not validated, filtered, or sanitized |\n")
    lines.append("| A04:2021 | Insecure Design | Missing or ineffective control design flaws |\n")
    lines.append("| A05:2021 | Security Misconfiguration | Missing security hardening or improperly configured permissions |\n")
    lines.append("| A06:2021 | Vulnerable and Outdated Components | Using components with known vulnerabilities |\n")
    lines.append("| A07:2021 | Identification and Authentication Failures | Authentication and session management issues |\n")
    lines.append("| A08:2021 | Software and Data Integrity Failures | Code and infrastructure that does not protect against integrity violations |\n")
    lines.append("| A09:2021 | Security Logging and Monitoring Failures | Insufficient logging and monitoring |\n")
    lines.append("| A10:2021 | Server-Side Request Forgery (SSRF) | Fetching remote resources without validating the URL |\n")
    
    lines.append("\n**Reference**: For complete information, visit https://owasp.org/Top10/\n\n")
    
    return ''.join(lines)


def generate_methodology_details() -> str:
    """
    Generate Appendix C: Detailed Methodology.
    """
    lines = []
    lines.append("### Appendix C: Detailed Testing Methodology\n\n")
    
    lines.append("#### Information Gathering Phase\n")
    lines.append("1. **Network Scanning**: Nmap TCP Connect scan across all 65535 ports\n")
    lines.append("2. **Service Detection**: Version detection and OS fingerprinting\n")
    lines.append("3. **WHOIS Lookup**: Domain registration and ownership information (public targets only)\n")
    lines.append("4. **DNS Enumeration**: Subdomain discovery and DNS record analysis (public targets only)\n\n")
    
    lines.append("#### Vulnerability Analysis Phase\n")
    lines.append("1. **Version Mapping**: Identified service versions mapped to CVE database\n")
    lines.append("2. **Risk Assessment**: AI-powered analysis of vulnerability severity and exploitability\n")
    lines.append("3. **Prioritization**: Vulnerabilities ranked by risk level and potential impact\n\n")
    
    lines.append("#### Web Application Testing Phase\n")
    lines.append("1. **Directory Enumeration**: Dirsearch with comprehensive wordlists\n")
    lines.append("2. **AI-RAG Analysis**: Vector database similarity search for security patterns\n")
    lines.append("3. **Playwright Automation**: Browser-based analysis of high-risk paths\n")
    lines.append("4. **Content Analysis**: Detection of sensitive information exposure\n\n")
    
    lines.append("#### SQL Injection Testing Phase\n")
    lines.append("1. **Endpoint Selection**: AI-powered pruning of candidate injection points\n")
    lines.append("2. **SQLMap Testing**: Automated injection testing with risk level 2, level 3\n")
    lines.append("3. **Database Enumeration**: Extraction of database metadata when vulnerabilities found\n")
    lines.append("4. **Impact Analysis**: AI assessment of exploitation scenarios and remediation\n\n")
    
    lines.append("#### Authentication Security Testing Phase\n")
    lines.append("1. **Login Detection**: Identification of authentication endpoints\n")
    lines.append("2. **Response Analysis**: Different credentials tested to detect enumeration vulnerabilities\n")
    lines.append("3. **Rate Limiting Check**: Testing for brute force protection mechanisms\n")
    lines.append("4. **Controlled Brute Force**: Limited credential testing (safety threshold: 10 attempts)\n\n")
    
    lines.append("#### Report Generation Phase\n")
    lines.append("1. **Data Aggregation**: Consolidation of findings from all phases\n")
    lines.append("2. **OWASP Classification**: AI-powered categorization into OWASP TOP 10 framework\n")
    lines.append("3. **Risk Scoring**: Automated severity assignment based on multiple factors\n")
    lines.append("4. **Remediation Guidance**: Actionable recommendations for each finding\n")
    lines.append("5. **Multi-Format Output**: Generation of Markdown, HTML, and JSON reports\n\n")
    
    return ''.join(lines)