"""
SQL Injection Report Generation

Generates SQL injection testing sections with detailed evidence.
"""

from typing import Dict, Any, Optional
from .markdown_utils import sanitize_table_cell, safe_truncate


def generate_sqli_section(phases_data: Dict[str, Any]) -> Optional[str]:
    """
    Generate SQL Injection Testing section.
    """
    sqli_data = phases_data.get('sqli_testing', {})
    
    if not sqli_data or sqli_data.get('endpoints_tested', 0) == 0:
        return None
    
    lines = []
    
    # Summary
    endpoints_tested = sqli_data.get('endpoints_tested', 0)
    vulnerable_endpoints = sqli_data.get('vulnerable_endpoints', 0)
    
    lines.append(f"**Endpoints Tested**: {endpoints_tested}\n")
    lines.append(f"**Vulnerable Endpoints**: {vulnerable_endpoints}\n")
    
    if vulnerable_endpoints == 0:
        lines.append("\n[+] **No SQL injection vulnerabilities were found.**\n")
        return ''.join(lines)
    
    lines.append("\n")
    
    # 5.1 Vulnerable Endpoints
    sqli_results = sqli_data.get('sqli_results', [])
    vulnerable_sqli = [r for r in sqli_results if r.get('vulnerable')]
    
    if vulnerable_sqli:
        lines.append("### 5.1 Vulnerable Endpoints\n")
        lines.append("The following endpoints were found to be vulnerable to SQL injection:\n\n")
        
        # Summary table
        lines.append("| URL | Injection Type | DBMS | Severity |\n")
        lines.append("|-----|----------------|------|----------|\n")
        
        for vuln in vulnerable_sqli:
            url = safe_truncate(vuln.get('url', 'N/A'), max_length=60, truncate_after_pipes=True)
            inj_type = sanitize_table_cell(vuln.get('injection_type', 'N/A'), max_length=30)
            dbms = sanitize_table_cell(vuln.get('dbms', 'Unknown'))
            severity = sanitize_table_cell(vuln.get('severity', 'High'))

            lines.append(f"| {url} | {inj_type} | {dbms} | {severity} |\n")
        
        lines.append("\n")
        
        # Detailed findings
        lines.append("### 5.2 Detailed SQL Injection Findings\n\n")
        
        for idx, vuln in enumerate(vulnerable_sqli, 1):
            vuln_id = f"VULN-SQLI-{idx:03d}"
            
            lines.append(f"#### {vuln_id}: {vuln.get('url', 'N/A')}\n\n")
            
            # Classification
            lines.append(f"**OWASP Category**: A03:2021 – Injection\n")
            lines.append(f"**Severity**: {vuln.get('severity', 'High')}\n")
            lines.append(f"**Injection Type**: {vuln.get('injection_type', 'N/A')}\n")
            lines.append(f"**Database Management System**: {vuln.get('dbms', 'Unknown')}\n")
            lines.append(f"**Related CVEs**: N/A\n\n")
            
            # Technical Risk
            lines.append("**Technical Risk**\n\n")
            ai_analysis = vuln.get('ai_analysis', {})
            if ai_analysis and ai_analysis.get('technical_risk'):
                lines.append(f"{ai_analysis['technical_risk']}\n\n")
            else:
                lines.append("SQL injection allows attackers to execute arbitrary database queries, potentially leading to data theft, data manipulation, or complete database compromise.\n\n")
            
            # Evidence
            lines.append("**Evidence**\n\n")
            
            # Command used
            command = vuln.get('command', '')
            if command:
                lines.append(f"**Command Used**:\n```bash\n{command}\n```\n\n")
            
            # Vulnerable parameter
            param = vuln.get('vulnerable_parameter', '')
            if param:
                lines.append(f"**Vulnerable Parameter**: `{param}`\n\n")
            
            # Payloads
            payloads = vuln.get('successful_payloads', [])
            if payloads:
                lines.append("**Successful Payloads**:\n")
                for payload in payloads[:5]:  # Top 5
                    lines.append(f"- `{payload}`\n")
                lines.append("\n")
            
            # Database info
            db_info = vuln.get('database_info', {})
            if db_info:
                lines.append("**Database Information Extracted**:\n")
                if db_info.get('current_user'):
                    lines.append(f"- Current User: `{db_info['current_user']}`\n")
                if db_info.get('current_db'):
                    lines.append(f"- Current Database: `{db_info['current_db']}`\n")
                if db_info.get('version'):
                    lines.append(f"- Database Version: `{db_info['version']}`\n")
                
                # Tables enumerated
                tables = db_info.get('tables', [])
                if tables:
                    lines.append(f"- Tables Found: {len(tables)}\n")
                    lines.append("  - " + ", ".join(f"`{t}`" for t in tables[:5]) + "\n")
                
                lines.append("\n")
            
            # AI Impact Analysis
            if ai_analysis:
                impact = ai_analysis.get('impact', '')
                if impact:
                    lines.append(f"**Impact Assessment**\n\n{impact}\n\n")
            
            # Remediation
            lines.append("**Remediation**\n\n")
            
            remediation_steps = ai_analysis.get('remediation_steps', []) if ai_analysis else []
            
            if remediation_steps:
                for step in remediation_steps:
                    lines.append(f"- {step}\n")
            else:
                # Default remediation
                lines.append("- Use parameterized queries (prepared statements) instead of dynamic SQL\n")
                lines.append("- Implement input validation and sanitization for all user inputs\n")
                lines.append("- Apply the principle of least privilege for database accounts\n")
                lines.append("- Enable web application firewall (WAF) with SQL injection rules\n")
                lines.append("- Use ORM (Object-Relational Mapping) frameworks where possible\n")
            
            lines.append("\n")
            
            # References
            lines.append("**References**\n\n")
            lines.append("- OWASP: https://owasp.org/Top10/A03_2021-Injection/\n")
            lines.append("- CWE-89: SQL Injection\n")
            lines.append("- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html\n")
            
            lines.append("\n---\n\n")
    
    return ''.join(lines)