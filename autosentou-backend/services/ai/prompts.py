"""
Centralized AI Prompts for AutoSentou

This file contains all AI prompts used throughout the application.
Benefits:
- Easy to view and modify all prompts in one place
- Consistent prompt formatting
- Version control for prompt engineering
- A/B testing different prompt versions
"""
import json
from typing import List, Dict, Any


# ==============================================================================
# OWASP TOP 10 2021 Reference (used across multiple prompts)
# ==============================================================================

OWASP_TOP_10_2021 = """
OWASP TOP 10 2021 CATEGORIES:
- A01:2021 - Broken Access Control (IDOR, missing authorization, path traversal)
- A02:2021 - Cryptographic Failures (weak encryption, exposed secrets, plain text passwords)
- A03:2021 - Injection (SQLi, XSS, Command Injection, LDAP, NoSQL, etc.)
- A04:2021 - Insecure Design (business logic flaws, insecure architecture)
- A05:2021 - Security Misconfiguration (default configs, exposed admin panels, unnecessary features)
- A06:2021 - Vulnerable and Outdated Components (outdated libraries with known CVEs)
- A07:2021 - Identification and Authentication Failures (weak password policy, no MFA, session issues)
- A08:2021 - Software and Data Integrity Failures (unsigned updates, insecure deserialization)
- A09:2021 - Security Logging and Monitoring Failures (missing logs, no alerting)
- A10:2021 - Server-Side Request Forgery (SSRF)
"""

RISK_LEVEL_CRITERIA = """
RISK LEVEL CRITERIA:
- Critical: Immediate exploitation possible, catastrophic impact (RCE, auth bypass, data breach)
- High: Direct exploitation possible, significant impact (SQLi, XSS, privilege escalation)
- Medium: Requires additional steps, moderate impact (info disclosure, business logic bypass)
- Low: Minimal impact, requires extensive prerequisites (missing headers, minor info leakage)
"""


# ==============================================================================
# Web Analysis Prompts
# ==============================================================================

def get_web_analysis_single_page_prompt(
    url: str,
    title: str,
    visible_text: str,
    findings_context: str = ""
) -> str:
    """
    Prompt for analyzing a single web page for security vulnerabilities.
    Used in web_analysis.py
    """
    return f"""You are an expert penetration tester analyzing a web page for security vulnerabilities.
Testing Framework: OWASP Testing Guide v4.0 & OWASP Top 10 2021

URL: {url}
Title: {title}

Page Content (first 8000 chars):
{visible_text[:8000]}

Previously discovered findings (reuse IDs for similar vulnerabilities):
{findings_context if findings_context else "None yet"}

Analyze this page and provide a structured JSON security report following professional pentesting standards:

{{
    "page_type": "LoginPage | AdminPanel | API | Dashboard | Form | ContactPage | FileUpload | Other",
    "findings": [
        {{
            "id": "vuln-XXX",
            "owasp_category": "A01:2021-Broken Access Control | A02:2021-Cryptographic Failures | A03:2021-Injection | A04:2021-Insecure Design | A05:2021-Security Misconfiguration | A06:2021-Vulnerable Components | A07:2021-Authentication Failures | A08:2021-Data Integrity Failures | A09:2021-Logging Failures | A10:2021-SSRF",
            "risk_level": "Critical | High | Medium | Low",
            "vector": "SQL Injection | XSS (Stored/Reflected) | CSRF | IDOR | Path Traversal | File Upload | Open Redirect | Info Disclosure | Hardcoded Credentials | Weak Authentication | Missing Access Control | etc.",
            "title": "Short descriptive title (e.g., 'SQL Injection in Login Form')",
            "description": "Clear description of the vulnerability and its impact",
            "evidence": "Specific code snippets, form fields, or page elements proving the vulnerability exists",
            "method": "GET | POST | PUT | DELETE | PATCH | ''",
            "parameters": ["param1", "param2"],
            "payload": ["' OR '1'='1", "<script>alert(1)</script>", "../../../etc/passwd"],
            "affected_urls": ["{url}"],
            "remediation": "Specific remediation steps (e.g., 'Use parameterized queries', 'Implement input validation')"
        }}
    ],
    "technologies": ["React 18.2", "Express.js", "MySQL"],
    "summary": "Brief summary of security posture and key findings"
}}

{OWASP_TOP_10_2021}

{RISK_LEVEL_CRITERIA}

CRITICAL RULES:
1. Only report findings with CONCRETE EVIDENCE from the page content
2. No speculation - if unsure, don't report it
3. Reuse finding IDs (vuln-XXX) for the same vulnerability across pages
4. Provide realistic, working payloads
5. Map each finding to correct OWASP 2021 category
6. Assign accurate risk level (Critical/High/Medium/Low)
7. Return ONLY valid JSON, no markdown code blocks

Respond strictly in JSON format:"""


def get_web_analysis_batch_prompt(
    batch_pages: List[Dict[str, Any]],
    findings_context: str = ""
) -> str:
    """
    Prompt for batch analysis of multiple web pages.
    Reduces API calls by analyzing multiple pages in one request.
    Used in web_analysis.py
    """
    # Build page summaries
    page_summaries = []
    for idx, page_data in enumerate(batch_pages, 1):
        url = page_data["url"]
        title = page_data.get("title", "")
        visible_text = page_data.get("visible_text", "")[:4000]  # Reduced for batching

        page_summary = f"""
PAGE {idx}:
URL: {url}
Title: {title}
Content (first 4000 chars):
{visible_text}
---"""
        page_summaries.append(page_summary)

    pages_content = "\n\n".join(page_summaries)

    return f"""You are an expert penetration tester analyzing MULTIPLE web pages for security vulnerabilities.
Testing Framework: OWASP Testing Guide v4.0 & OWASP Top 10 2021

Previously discovered findings (reuse IDs for similar vulnerabilities):
{findings_context if findings_context else "None yet"}

ANALYZE THE FOLLOWING {len(batch_pages)} PAGES:
{pages_content}

For EACH page above, provide a structured JSON security report following professional pentesting standards.

Respond with a JSON ARRAY (one analysis per page):

[
  {{
    "url": "the page URL",
    "page_type": "LoginPage | AdminPanel | API | Dashboard | Form | ContactPage | FileUpload | Other",
    "findings": [
      {{
        "id": "vuln-XXX",
        "owasp_category": "A01:2021-Broken Access Control | A02:2021-Cryptographic Failures | A03:2021-Injection | A04:2021-Insecure Design | A05:2021-Security Misconfiguration | A06:2021-Vulnerable Components | A07:2021-Authentication Failures | A08:2021-Data Integrity Failures | A09:2021-Logging Failures | A10:2021-SSRF",
        "risk_level": "Critical | High | Medium | Low",
        "vector": "SQL Injection | XSS | CSRF | IDOR | Path Traversal | etc.",
        "title": "Short descriptive title",
        "description": "Clear description of the vulnerability",
        "evidence": "Specific evidence from page content",
        "method": "GET | POST | PUT | DELETE | ''",
        "parameters": ["param1", "param2"],
        "payload": ["payload1", "payload2"],
        "affected_urls": ["url"],
        "remediation": "Specific remediation steps"
      }}
    ],
    "technologies": ["React", "Express.js"],
    "summary": "Brief summary"
  }},
  ... repeat for each page ...
]

{OWASP_TOP_10_2021}

{RISK_LEVEL_CRITERIA}

CRITICAL RULES:
1. Only report findings with CONCRETE EVIDENCE from page content
2. No speculation - if unsure, don't report it
3. Reuse finding IDs for same vulnerabilities
4. Provide realistic payloads
5. Map to correct OWASP 2021 category
6. Return ONLY valid JSON array, no markdown code blocks
7. Include ALL {len(batch_pages)} pages in response array

Respond strictly in JSON array format:"""


# ==============================================================================
# Vulnerability Categorization Prompts
# ==============================================================================

def get_single_categorization_prompt(finding: Dict[str, Any]) -> str:
    """
    Prompt for categorizing a single vulnerability finding.
    Used in ai_categorizer.py
    """
    return f"""You are a cybersecurity expert specializing in vulnerability assessment and OWASP Top 10.

Analyze the following vulnerability finding and provide a detailed categorization.

**Finding Information:**
- Title: {finding.get('title', 'N/A')}
- Description: {finding.get('description', 'N/A')}
- Type: {finding.get('finding_type', 'N/A')}
- URL: {finding.get('url', 'N/A')}
- Service: {finding.get('service', 'N/A')}
- Port: {finding.get('port', 'N/A')}
- CVE ID: {finding.get('cve_id', 'N/A')}
- Evidence: {json.dumps(finding.get('evidence', {}), indent=2)}

**Task:**
Categorize this vulnerability using the OWASP Top 10 2021 framework.

{OWASP_TOP_10_2021}

**Respond ONLY with valid JSON in this exact format:**
{{
  "severity": "Critical|High|Medium|Low",
  "owasp_category": "A0X:2021 - Full Category Name",
  "cwe_id": "CWE-XXX",
  "category": "Brief descriptive category name",
  "remediation": "Detailed remediation steps (2-3 sentences)",
  "cvss_estimate": 0.0,
  "reasoning": "Brief explanation of why this categorization (1-2 sentences)"
}}

Provide your response as valid JSON only, no other text."""


def get_batch_categorization_prompt(findings: List[Dict[str, Any]]) -> str:
    """
    Prompt for batch categorization of multiple findings.
    Reduces API calls by processing multiple findings at once.
    Used in findings_populator.py (new implementation)
    """
    findings_json = []
    for idx, finding in enumerate(findings, 1):
        findings_json.append({
            'id': idx,
            'title': finding.get('title', 'N/A'),
            'description': finding.get('description', 'N/A'),
            'finding_type': finding.get('finding_type', 'N/A'),
            'url': finding.get('url', 'N/A'),
            'service': finding.get('service', 'N/A'),
            'cve_id': finding.get('cve_id', 'N/A')
        })

    return f"""You are a cybersecurity expert specializing in vulnerability assessment and OWASP Top 10.

Categorize the following {len(findings)} vulnerabilities according to OWASP Top 10 2021:

{json.dumps(findings_json, indent=2)}

{OWASP_TOP_10_2021}

Return a JSON array with categorization for each vulnerability:

[
  {{
    "id": 1,
    "severity": "Critical|High|Medium|Low",
    "owasp_category": "A0X:2021 - Full Category Name",
    "cwe_id": "CWE-XXX",
    "category": "Brief descriptive category name",
    "remediation": "Detailed remediation steps (2-3 sentences)",
    "cvss_estimate": 0.0,
    "reasoning": "Brief explanation (1-2 sentences)"
  }},
  {{
    "id": 2,
    "severity": "Critical|High|Medium|Low",
    "owasp_category": "A0X:2021 - Full Category Name",
    "cwe_id": "CWE-XXX",
    "category": "Brief descriptive category name",
    "remediation": "Detailed remediation steps",
    "cvss_estimate": 0.0,
    "reasoning": "Brief explanation"
  }},
  ... etc ...
]

IMPORTANT:
1. Return results in the SAME ORDER as the input
2. Include ALL {len(findings)} findings in the response
3. Each result must have the same "id" as the corresponding input
4. Provide accurate OWASP 2021 categories and severity levels
5. Return ONLY valid JSON array, no markdown code blocks

Respond strictly in JSON array format:"""


# ==============================================================================
# Version Information
# ==============================================================================

PROMPT_VERSION = "1.0.0"
LAST_UPDATED = "2025-01-18"

"""
Version History:
- 1.0.0 (2025-01-18): Initial centralized prompts
  - Web analysis prompts (single and batch)
  - Vulnerability categorization prompts (single and batch)
  - OWASP Top 10 2021 reference
"""
