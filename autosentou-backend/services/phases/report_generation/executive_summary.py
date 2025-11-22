"""
Executive Summary Generation - OWASP-Based Professional Format

Generates executive summary with risk tables following professional pentesting report structure.
Based on OWASP Top 10 2021 categorization and High/Medium/Low risk levels.
"""

from typing import Dict, Any, List
from collections import Counter, defaultdict
from models import Job


def generate_executive_summary_section(job: Job, phases_data: Dict[str, Any]) -> str:
    """
    Generate executive summary with risk tables matching professional pentest report format.

    Tables Generated:
    - Table 1: Risk Summary
    - Table 2: Risk Level Definitions
    - Table 3: Risk Level & Quantity (per target)
    - Table 4: Vulnerability Names (OWASP categories with counts)
    - Table 5: Vulnerability Distribution (detailed list)
    """
    lines = []

    # Collect ALL findings from ALL phases
    all_findings = []

    # 1. Web Analysis findings (AI-tested vulnerabilities)
    web_analysis_data = phases_data.get('web_analysis', {})
    for finding in web_analysis_data.get('findings', []):
        all_findings.append({
            'title': finding.get('title', 'Web Vulnerability'),
            'severity': finding.get('severity', 'Medium'),
            'owasp_category': finding.get('owasp_category', 'Unknown'),
            'cwe_id': finding.get('cwe_id', ''),
            'url': finding.get('url', job.target),
            'description': finding.get('description', ''),
            'remediation': finding.get('remediation', ''),
            'finding_type': 'web_analysis'
        })

    # 2. CVE findings from Vulnerability Analysis
    vuln_data = phases_data.get('vulnerability_analysis', {})
    service_analysis = vuln_data.get('service_analysis', {})
    for service in service_analysis.get('services', []):
        for vuln in service.get('vulnerabilities', []):
            all_findings.append({
                'title': vuln.get('cve_id', 'CVE Vulnerability'),
                'severity': vuln.get('severity', 'Medium'),
                'owasp_category': 'A06:2021-Vulnerable and Outdated Components',
                'cwe_id': '',
                'url': f"{job.target}:{service.get('port', '')}",
                'description': vuln.get('description', ''),
                'remediation': vuln.get('remediation', ''),
                'finding_type': 'cve',
                'service': service.get('service', ''),
                'port': service.get('port', '')
            })

    # 3. SQL Injection findings
    sqli_data = phases_data.get('sqli_testing', {})
    for result in sqli_data.get('sqli_results', []):
        if result.get('vulnerable'):
            all_findings.append({
                'title': 'SQL Injection',
                'severity': result.get('severity', 'High'),
                'owasp_category': 'A03:2021-Injection',
                'cwe_id': 'CWE-89',
                'url': result.get('url', job.target),
                'description': f"SQL Injection found at {result.get('url')}",
                'remediation': 'Use parameterized queries',
                'finding_type': 'sqli',
                'parameter': result.get('parameter', '')
            })

    # 4. Authentication findings
    auth_data = phases_data.get('authentication_testing', {})
    for test in auth_data.get('login_response_tests', []):
        if test.get('ai_analysis', {}).get('account_enumeration_possible'):
            all_findings.append({
                'title': 'Account Enumeration',
                'severity': test.get('ai_analysis', {}).get('classification', {}).get('severity', 'Medium'),
                'owasp_category': 'A07:2021-Identification and Authentication Failures',
                'cwe_id': 'CWE-204',
                'url': test.get('url', job.target),
                'description': f"Account enumeration possible at {test.get('url')}",
                'remediation': 'Use consistent error messages',
                'finding_type': 'authentication'
            })

    # Section Header
    lines.append("## Executive Summary\n\n")
    lines.append("The following security vulnerabilities were identified during the penetration testing engagement:\n\n")

    # Table 1: Risk Summary
    lines.append(_generate_risk_summary_table(all_findings))

    # Table 2: Risk Level Definitions
    lines.append("\n### Risk Level Definitions\n\n")
    lines.append(_generate_risk_level_definition_table())

    # Table 3: Risk Level & Quantity
    lines.append("\n### Risk Level Distribution\n\n")
    lines.append(_generate_risk_count_table(all_findings))

    # Table 4: Vulnerability Categories (OWASP)
    lines.append("\n### Vulnerability Categories Identified\n\n")
    lines.append(_generate_vulnerability_names_table(all_findings))

    # Table 5: Vulnerability Distribution
    lines.append("\n### Vulnerability Distribution by Target\n\n")
    lines.append(_generate_vulnerability_distribution_table(all_findings, job))

    return ''.join(lines)


def _normalize_severity(severity: str) -> str:
    """Normalize severity to standard levels"""
    if not severity:
        return 'Low'
    s = severity.lower().strip()
    if s in ['critical', 'crit']:
        return 'Critical'
    elif s in ['high', 'hi']:
        return 'High'
    elif s in ['medium', 'med', 'moderate']:
        return 'Medium'
    else:
        return 'Low'


def _generate_risk_summary_table(findings: List[Dict[str, Any]]) -> str:
    """Generate Table 1: Risk Summary"""
    critical = len([f for f in findings if _normalize_severity(f.get('severity')) == 'Critical'])
    high = len([f for f in findings if _normalize_severity(f.get('severity')) == 'High'])
    medium = len([f for f in findings if _normalize_severity(f.get('severity')) == 'Medium'])
    low = len([f for f in findings if _normalize_severity(f.get('severity')) == 'Low'])
    total = critical + high + medium + low

    lines = []
    lines.append("**Table 1: Risk Summary**\n\n")
    lines.append("| Risk Level | Count |\n")
    lines.append("|-----------|-------|\n")
    lines.append(f"| Critical | {critical} |\n")
    lines.append(f"| High | {high} |\n")
    lines.append(f"| Medium | {medium} |\n")
    lines.append(f"| Low | {low} |\n")
    lines.append(f"| **Total** | **{total}** |\n")

    return ''.join(lines)


def _generate_risk_level_definition_table() -> str:
    """Generate Table 2: Risk Level Definitions"""
    lines = []
    lines.append("**Table 2: Risk Level Definitions**\n\n")
    lines.append("| Risk Level | Definition |\n")
    lines.append("|-----------|------------|\n")
    lines.append("| **Critical** | Directly threatens application, OS, or web server security. May lead to full system control, access to sensitive data, or malicious code execution. |\n")
    lines.append("| **High** | Unauthorized access with significant impact. May lead to data breach, remote code execution, or authentication bypass. |\n")
    lines.append("| **Medium** | Unauthorized access with moderate impact. May lead to information disclosure or business logic bypass. |\n")
    lines.append("| **Low** | Unnecessary information disclosure. May provide reference information for attackers. |\n")

    return ''.join(lines)


def _generate_risk_count_table(findings: List[Dict[str, Any]]) -> str:
    """Generate Table 3: Risk Level & Quantity per Target"""
    # Group findings by target URL
    target_risks = defaultdict(lambda: {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0})

    for finding in findings:
        url = finding.get('url', 'Unknown')
        base_url = _extract_base_url(url)
        severity = _normalize_severity(finding.get('severity'))
        target_risks[base_url][severity] += 1

    lines = []
    lines.append("**Table 3: Risk Level & Quantity by Target**\n\n")
    lines.append("| Target | Risk Level | Critical | High | Medium | Low |\n")
    lines.append("|--------|------------|----------|------|--------|-----|\n")

    if not target_risks:
        lines.append("| - | None | 0 | 0 | 0 | 0 |\n")
    else:
        for target, risks in target_risks.items():
            # Determine overall risk level for this target
            if risks['Critical'] > 0:
                overall = 'Critical'
            elif risks['High'] > 0:
                overall = 'High'
            elif risks['Medium'] > 0:
                overall = 'Medium'
            elif risks['Low'] > 0:
                overall = 'Low'
            else:
                overall = 'None'

            lines.append(f"| {target} | {overall} | {risks['Critical']} | {risks['High']} | {risks['Medium']} | {risks['Low']} |\n")

    return ''.join(lines)


def _generate_vulnerability_names_table(findings: List[Dict[str, Any]]) -> str:
    """Generate Table 4: Vulnerability Names with counts per target and severity"""
    # Group by target -> vulnerability name -> severity counts
    target_vulns = defaultdict(lambda: defaultdict(lambda: {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}))

    for finding in findings:
        url = finding.get('url', 'Unknown')
        base_url = _extract_base_url(url)
        title = finding.get('title', finding.get('owasp_category', 'Unknown'))
        severity = _normalize_severity(finding.get('severity'))
        target_vulns[base_url][title][severity] += 1

    lines = []
    lines.append("**Table 4: Vulnerability Names by Target**\n\n")
    lines.append("| Target | Vulnerability Name | Critical | High | Medium | Low |\n")
    lines.append("|--------|-------------------|----------|------|--------|-----|\n")

    if not target_vulns:
        lines.append("| - | No vulnerabilities detected | 0 | 0 | 0 | 0 |\n")
    else:
        total_critical = total_high = total_medium = total_low = 0

        for target, vulns in target_vulns.items():
            for vuln_name, severity_counts in vulns.items():
                c = severity_counts['Critical']
                h = severity_counts['High']
                m = severity_counts['Medium']
                l = severity_counts['Low']

                total_critical += c
                total_high += h
                total_medium += m
                total_low += l

                lines.append(f"| {target} | {vuln_name} | {c} | {h} | {m} | {l} |\n")

        # Total row
        lines.append(f"| **Total** | - | **{total_critical}** | **{total_high}** | **{total_medium}** | **{total_low}** |\n")

    return ''.join(lines)


def _generate_vulnerability_distribution_table(findings: List[Dict[str, Any]], job: Job) -> str:
    """Generate Table 5: Vulnerability Distribution - Detailed list like professional pentest report"""
    lines = []
    lines.append("**Table 5: Vulnerability Distribution**\n\n")
    lines.append("| Vulnerability Name | Count | Risk Level | IP / URL / Service |\n")
    lines.append("|-------------------|-------|------------|--------------------|\n")

    if not findings:
        lines.append(f"| No vulnerabilities detected | 0 | - | {job.target} |\n")
    else:
        # Group findings by vulnerability name
        vuln_groups = defaultdict(list)
        for finding in findings:
            title = finding.get('title', finding.get('owasp_category', 'Unknown'))
            vuln_groups[title].append(finding)

        for vuln_name, vulns in vuln_groups.items():
            count = len(vulns)
            # Get highest severity for this vulnerability type
            severities = [_normalize_severity(v.get('severity')) for v in vulns]
            severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
            highest_severity = min(severities, key=lambda s: severity_order.get(s, 4))

            # Build location string
            locations = []
            for v in vulns:
                url = v.get('url', job.target)
                port = v.get('port', '')
                service = v.get('service', '')

                if port and service:
                    loc = f"{url}<br/>tcp / {port} / {service}"
                elif port:
                    loc = f"{url}<br/>port {port}"
                else:
                    loc = url

                if loc not in locations:
                    locations.append(loc)

            location_str = "<br/>".join(locations[:3])  # Limit to 3 locations
            if len(locations) > 3:
                location_str += f"<br/>... and {len(locations) - 3} more"

            lines.append(f"| {vuln_name} | {count} | {highest_severity} | {location_str} |\n")

    return ''.join(lines)


def _extract_base_url(url: str) -> str:
    """Extract base URL (protocol + host + port) from full URL"""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else parsed.netloc
    return base if base else url
