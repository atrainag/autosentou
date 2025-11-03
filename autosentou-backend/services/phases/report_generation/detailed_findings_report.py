"""
Detailed Findings Report Generator
Generates a comprehensive, professional report with evidence, remediation, and technical details.
This is the "Goldilocks" report - detailed enough for compliance/audits but automated.
"""
from typing import Dict, Any, List, Optional
from models import Job, Finding
from datetime import datetime
from sqlalchemy import func
from database import SessionLocal


def generate_detailed_findings_report(job: Job, phases_data: Dict[str, Any], db_session) -> str:
    """
    Generate a comprehensive detailed findings report.

    This report includes:
    - Executive summary
    - Scope and methodology
    - Findings grouped by severity with evidence
    - Technical test results
    - Prioritized recommendations
    - Appendix

    Args:
        job: Job object
        phases_data: All phases data
        db_session: Database session

    Returns:
        Markdown content for the detailed report
    """
    lines = []

    # Header
    lines.append("# Penetration Testing Report - Detailed Findings\n\n")
    lines.append(f"**Target:** {job.target}\n\n")
    lines.append(f"**Report Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    lines.append(f"**Job ID:** {job.id}\n\n")
    lines.append("**Classification:** Confidential\n\n")
    lines.append("---\n\n")

    # Confidentiality Notice
    lines.append("## Confidentiality Notice\n\n")
    lines.append("This document is marked as **CONFIDENTIAL** and contains sensitive information about network ")
    lines.append("architecture, system configurations, and security vulnerabilities. This report is intended solely ")
    lines.append("for internal security risk management assessment. Unauthorized disclosure, copying, or distribution ")
    lines.append("of this document may constitute a breach of confidentiality and may result in legal action.\n\n")
    lines.append("---\n\n")

    # Table of Contents
    lines.append(_generate_toc())

    # 1. Executive Summary
    lines.append(_generate_executive_summary_section(job, phases_data, db_session))

    # 2. Testing Scope and Methodology
    lines.append(_generate_scope_methodology_section(job, phases_data))

    # 3. Findings by Severity
    lines.append(_generate_findings_by_severity_section(job, db_session))

    # 4. Technical Test Results
    lines.append(_generate_technical_results_section(phases_data))

    # 5. Recommendations
    lines.append(_generate_recommendations_section(job, db_session))

    # 6. Conclusion
    lines.append(_generate_conclusion_section(job, db_session))

    # 7. Appendix
    lines.append(_generate_appendix_section(phases_data))

    return ''.join(lines)


def _generate_toc() -> str:
    """Generate table of contents."""
    lines = []
    lines.append("## Table of Contents\n\n")
    lines.append("1. Executive Summary\n")
    lines.append("2. Testing Scope and Methodology\n")
    lines.append("   - 2.1 Scope and Limitations\n")
    lines.append("   - 2.2 Target Information\n")
    lines.append("   - 2.3 Testing Methodology\n")
    lines.append("   - 2.4 Risk Rating Methodology\n")
    lines.append("3. Security Findings by Severity\n")
    lines.append("   - 3.1 Critical Severity Findings\n")
    lines.append("   - 3.2 High Severity Findings\n")
    lines.append("   - 3.3 Medium Severity Findings\n")
    lines.append("   - 3.4 Low Severity Findings\n")
    lines.append("4. Technical Test Results\n")
    lines.append("   - 4.1 Network Services Discovery\n")
    lines.append("   - 4.2 Web Application Enumeration\n")
    lines.append("   - 4.3 SQL Injection Testing\n")
    lines.append("   - 4.4 Authentication Security Testing\n")
    lines.append("5. Recommendations\n")
    lines.append("6. Conclusion\n")
    lines.append("7. Appendix\n\n")
    lines.append("---\n\n")
    return ''.join(lines)


def _generate_executive_summary_section(job: Job, phases_data: Dict[str, Any], db_session) -> str:
    """Generate executive summary section."""
    lines = []
    lines.append("## 1. Executive Summary\n\n")

    # Get findings statistics
    total_findings = db_session.query(func.count(Finding.id)).filter(Finding.job_id == job.id).scalar() or 0
    severity_counts = db_session.query(
        Finding.severity,
        func.count(Finding.id)
    ).filter(Finding.job_id == job.id).group_by(Finding.severity).all()
    by_severity = {severity: count for severity, count in severity_counts}

    critical = by_severity.get('Critical', 0)
    high = by_severity.get('High', 0)
    medium = by_severity.get('Medium', 0)
    low = by_severity.get('Low', 0)

    lines.append(f"This penetration test was conducted on **{job.target}** using the Autosentou automated ")
    lines.append("penetration testing platform. The assessment followed industry-standard methodologies including:\n\n")
    lines.append("- Information Gathering and Network Reconnaissance (Nmap)\n")
    lines.append("- Vulnerability Analysis and CVE Detection (NVD Database)\n")
    lines.append("- Web Application Enumeration (Dirsearch)\n")
    lines.append("- SQL Injection Testing (SQLMap)\n")
    lines.append("- Authentication Security Testing (Hydra/Medusa)\n\n")

    lines.append(f"### Key Findings Summary\n\n")
    lines.append(f"The assessment identified **{total_findings} security findings** across various categories:\n\n")

    # Summary table
    lines.append("| Severity | Count | Immediate Action Required |\n")
    lines.append("|----------|-------|---------------------------|\n")
    lines.append(f"| **Critical** | {critical} | {'Yes - Immediate remediation' if critical > 0 else 'N/A'} |\n")
    lines.append(f"| **High** | {high} | {'Yes - Prompt attention needed' if high > 0 else 'N/A'} |\n")
    lines.append(f"| **Medium** | {medium} | {'Plan for next cycle' if medium > 0 else 'N/A'} |\n")
    lines.append(f"| **Low** | {low} | {'Monitor and plan' if low > 0 else 'N/A'} |\n\n")

    # Risk assessment
    if critical > 0:
        lines.append(f"### ⚠️ Overall Risk Level: CRITICAL\n\n")
        lines.append(f"This system has **{critical} critical-severity vulnerabilities** that require immediate attention. ")
        lines.append("These vulnerabilities could lead to complete system compromise, data breach, or service disruption.\n\n")
    elif high > 0:
        lines.append(f"### ⚠️ Overall Risk Level: HIGH\n\n")
        lines.append(f"This system has **{high} high-severity vulnerabilities** that should be addressed promptly. ")
        lines.append("These vulnerabilities could lead to significant security breaches if exploited.\n\n")
    elif medium > 0:
        lines.append(f"### ℹ️ Overall Risk Level: MODERATE\n\n")
        lines.append(f"This system has **{medium} medium-severity findings**. While not immediately exploitable, ")
        lines.append("these should be addressed in the next security cycle.\n\n")
    else:
        lines.append(f"### ✓ Overall Risk Level: LOW\n\n")
        lines.append("No critical or high severity findings were identified. The system demonstrates a good security posture.\n\n")

    lines.append("---\n\n")
    return ''.join(lines)


def _generate_scope_methodology_section(job: Job, phases_data: Dict[str, Any]) -> str:
    """Generate scope and methodology section."""
    lines = []
    lines.append("## 2. Testing Scope and Methodology\n\n")

    info_data = phases_data.get('information_gathering', {})
    is_local_target = info_data.get('is_local_target', False)

    # 2.1 Scope and Limitations
    lines.append("### 2.1 Scope and Limitations\n\n")
    lines.append("This penetration testing assessment was conducted using automated scanning tools and follows ")
    lines.append("a standardized methodology. The following scope and limitations apply:\n\n")
    lines.append("**In Scope:**\n")
    lines.append(f"- Target System: {job.target}\n")
    lines.append("- Automated vulnerability scanning and detection\n")
    lines.append("- Common web application vulnerabilities (OWASP Top 10)\n")
    lines.append("- Network service enumeration and CVE analysis\n")
    lines.append("- SQL injection and authentication testing\n\n")

    lines.append("**Limitations:**\n")
    lines.append("- **Automated Testing Only**: This assessment utilizes automated security scanning tools. ")
    lines.append("Manual penetration testing and human exploitation attempts were not performed.\n")
    lines.append("- **Non-Destructive Testing**: All tests are designed to identify vulnerabilities without ")
    lines.append("causing service disruption or data loss.\n")
    lines.append("- **Point-in-Time Assessment**: Results represent the security posture at the time of testing.\n")
    lines.append("- **Out of Scope**: Social engineering, denial-of-service attacks, physical security assessments, ")
    lines.append("and source code review were not performed.\n\n")

    if is_local_target:
        lines.append("**Note**: This is a local/private network target. WHOIS and DNS enumeration were not performed ")
        lines.append("as they are not applicable to private IP ranges.\n\n")

    # 2.2 Target Information
    lines.append("### 2.2 Target Information\n\n")
    lines.append(f"- **Target**: {job.target}\n")
    lines.append(f"- **Target Type**: {'Local/Private Network' if is_local_target else 'Public/External Network'}\n")
    lines.append(f"- **Scan Type**: Comprehensive Automated Assessment\n")
    lines.append(f"- **Test Date**: {datetime.now().strftime('%Y-%m-%d')}\n\n")

    # 2.3 Testing Methodology
    lines.append("### 2.3 Testing Methodology\n\n")
    lines.append("The assessment followed industry-standard penetration testing methodology based on OWASP and OSSTMM:\n\n")
    lines.append("**Phase 1: Information Gathering**\n")
    lines.append("- Network reconnaissance using Nmap\n")
    lines.append("- Service identification and version detection\n")
    lines.append("- Operating system fingerprinting\n\n")

    lines.append("**Phase 2: Vulnerability Analysis**\n")
    lines.append("- CVE database lookup via NVD API\n")
    lines.append("- Exploit database searching (ExploitDB, GitHub)\n")
    lines.append("- AI-powered vulnerability categorization\n\n")

    lines.append("**Phase 3: Web Application Testing**\n")
    lines.append("- Directory and file enumeration using Dirsearch\n")
    lines.append("- Sensitive path detection\n")
    lines.append("- AI-powered risk analysis of discovered paths\n\n")

    lines.append("**Phase 4: SQL Injection Testing**\n")
    lines.append("- Automated injection testing using SQLMap\n")
    lines.append("- Database enumeration on vulnerable endpoints\n\n")

    lines.append("**Phase 5: Authentication Testing**\n")
    lines.append("- Login page security analysis\n")
    lines.append("- Weak credential testing\n")
    lines.append("- Authentication bypass attempts\n\n")

    lines.append("**Phase 6: Report Generation**\n")
    lines.append("- Comprehensive documentation of findings\n")
    lines.append("- Evidence collection and archival\n\n")

    # 2.4 Risk Rating Methodology
    lines.append("### 2.4 Risk Rating Methodology\n\n")
    lines.append("Vulnerabilities are classified using the following severity levels:\n\n")
    lines.append("| Severity | Description | CVSS Score Range |\n")
    lines.append("|----------|-------------|------------------|\n")
    lines.append("| **Critical** | Vulnerabilities that can be exploited immediately with severe impact (e.g., remote code execution, complete system compromise) | 9.0 - 10.0 |\n")
    lines.append("| **High** | Vulnerabilities that are likely exploitable and could lead to significant security breaches (e.g., SQL injection, authentication bypass) | 7.0 - 8.9 |\n")
    lines.append("| **Medium** | Vulnerabilities that require specific conditions to exploit or have moderate impact (e.g., information disclosure, weak configurations) | 4.0 - 6.9 |\n")
    lines.append("| **Low** | Vulnerabilities with minimal immediate risk or require significant effort to exploit (e.g., minor information leakage) | 0.1 - 3.9 |\n\n")

    lines.append("Severity is determined through a combination of:\n")
    lines.append("1. CVSS (Common Vulnerability Scoring System) scores\n")
    lines.append("2. Exploit difficulty and availability\n")
    lines.append("3. Potential impact on confidentiality, integrity, and availability\n")
    lines.append("4. OWASP TOP 10 2021 classification\n")
    lines.append("5. AI-powered risk assessment using vulnerability knowledge base\n\n")

    lines.append("---\n\n")
    return ''.join(lines)


def _generate_findings_by_severity_section(job: Job, db_session) -> str:
    """Generate findings grouped by severity with evidence and remediation."""
    lines = []
    lines.append("## 3. Security Findings by Severity\n\n")

    lines.append("This section details all security findings identified during the assessment, ")
    lines.append("organized by severity level. Each finding includes:\n\n")
    lines.append("- **Description**: What the vulnerability is\n")
    lines.append("- **Evidence**: Proof of the vulnerability\n")
    lines.append("- **Impact**: Potential consequences if exploited\n")
    lines.append("- **Remediation**: How to fix the vulnerability\n")
    lines.append("- **References**: Links to CVE, OWASP, and other resources\n\n")

    # Get all findings grouped by severity
    severity_order = ['Critical', 'High', 'Medium', 'Low']

    for idx, severity in enumerate(severity_order, 1):
        findings = db_session.query(Finding).filter(
            Finding.job_id == job.id,
            Finding.severity == severity
        ).all()

        if findings:
            lines.append(f"### 3.{idx} {severity} Severity Findings\n\n")
            lines.append(f"**Total {severity} Findings: {len(findings)}**\n\n")

            for finding_idx, finding in enumerate(findings, 1):
                lines.append(_format_finding_detail(finding, f"3.{idx}.{finding_idx}"))
                lines.append("\n")
        else:
            lines.append(f"### 3.{idx} {severity} Severity Findings\n\n")
            lines.append(f"✓ No {severity.lower()} severity findings identified.\n\n")

    lines.append("---\n\n")
    return ''.join(lines)


def _format_finding_detail(finding: Finding, section_num: str) -> str:
    """Format a single finding with all details."""
    lines = []

    # Finding header
    lines.append(f"#### {section_num} {finding.title}\n\n")

    # Quick info table
    lines.append("| Attribute | Value |\n")
    lines.append("|-----------|-------|\n")
    lines.append(f"| **Severity** | {finding.severity} |\n")
    lines.append(f"| **Finding Type** | {finding.finding_type.upper() if finding.finding_type else 'N/A'} |\n")
    lines.append(f"| **OWASP Category** | {finding.owasp_category or 'N/A'} |\n")

    if finding.cve_id:
        lines.append(f"| **CVE ID** | [{finding.cve_id}](https://nvd.nist.gov/vuln/detail/{finding.cve_id}) |\n")
    if finding.cvss_score:
        lines.append(f"| **CVSS Score** | {finding.cvss_score} |\n")
    if finding.service:
        lines.append(f"| **Affected Service** | {finding.service} |\n")
    if finding.port:
        lines.append(f"| **Port** | {finding.port} |\n")
    if finding.url:
        lines.append(f"| **URL** | {finding.url} |\n")

    lines.append("\n")

    # Description
    lines.append("**Description:**\n\n")
    lines.append(f"{finding.description}\n\n")

    # Evidence (use poc field for text evidence)
    if finding.poc:
        lines.append("**Evidence:**\n\n")
        poc_text = finding.poc

        # Truncate long evidence
        if len(poc_text) > 2000:
            lines.append("```\n")
            lines.append(poc_text[:2000])
            lines.append("\n... [Evidence truncated. See raw outputs archive for full details]\n")
            lines.append("```\n\n")
        else:
            lines.append("```\n")
            lines.append(poc_text)
            lines.append("\n```\n\n")

    # Impact (generate if not present - stored in evidence JSON or generated dynamically)
    impact_text = None
    if finding.evidence and isinstance(finding.evidence, dict):
        impact_text = finding.evidence.get('impact')

    if not impact_text:
        # Generate generic impact based on severity and type
        if finding.severity == 'Critical':
            impact_text = "This critical vulnerability could lead to complete system compromise, unauthorized access to sensitive data, or complete service disruption."
        elif finding.severity == 'High':
            impact_text = "This high-severity vulnerability could lead to significant security breaches, data leakage, or partial system compromise."
        elif finding.severity == 'Medium':
            impact_text = "This medium-severity vulnerability could be exploited under specific conditions to gain unauthorized information or limited access."
        elif finding.severity == 'Low':
            impact_text = "This low-severity vulnerability has minimal immediate risk but should be addressed as part of security hardening."

    if impact_text:
        lines.append("**Impact:**\n\n")
        lines.append(f"{impact_text}\n\n")

    # Remediation
    if finding.remediation:
        lines.append("**Remediation:**\n\n")
        lines.append(f"{finding.remediation}\n\n")

    # References (stored in evidence JSON for CVEs, or generate from CVE ID)
    references = []

    # Extract from evidence JSON if available
    if finding.evidence and isinstance(finding.evidence, dict):
        refs_from_evidence = finding.evidence.get('references', [])
        if refs_from_evidence:
            references.extend(refs_from_evidence)

        # Add exploit URLs if available
        exploit_urls = finding.evidence.get('exploit_urls', [])
        if exploit_urls:
            references.extend(exploit_urls)

    # Add NVD link for CVEs
    if finding.cve_id and not any('nvd.nist.gov' in ref for ref in references):
        references.insert(0, f"https://nvd.nist.gov/vuln/detail/{finding.cve_id}")

    # Add OWASP link
    if finding.owasp_category and not any('owasp.org' in ref for ref in references):
        references.append("https://owasp.org/Top10/")

    if references:
        lines.append("**References:**\n\n")
        for ref in references:
            lines.append(f"- {ref}\n")
        lines.append("\n")

    lines.append("---\n\n")
    return ''.join(lines)


def _generate_technical_results_section(phases_data: Dict[str, Any]) -> str:
    """Generate technical test results section."""
    lines = []
    lines.append("## 4. Technical Test Results\n\n")
    lines.append("This section provides detailed technical information about the tests performed ")
    lines.append("and raw results obtained from various security scanning tools.\n\n")

    # 4.1 Network Services Discovery
    lines.append("### 4.1 Network Services Discovery\n\n")
    info_data = phases_data.get('information_gathering', {})
    if info_data:
        nmap_data = info_data.get('nmap', {})
        open_ports = nmap_data.get('open_ports', [])

        if open_ports:
            lines.append(f"**Open Ports Discovered: {len(open_ports)}**\n\n")
            lines.append("| Port | Protocol | Service | Version | State |\n")
            lines.append("|------|----------|---------|---------|-------|\n")

            for port in open_ports[:20]:  # Limit to first 20
                port_num = port.get('port', 'N/A')
                protocol = port.get('protocol', 'tcp')
                service = port.get('service', 'unknown')
                version = port.get('version', 'N/A')
                state = port.get('state', 'open')
                lines.append(f"| {port_num} | {protocol} | {service} | {version} | {state} |\n")

            if len(open_ports) > 20:
                lines.append(f"\n*... and {len(open_ports) - 20} more ports. See raw outputs for complete list.*\n")
            lines.append("\n")
        else:
            lines.append("No open ports discovered or scan not completed.\n\n")

        # OS Detection
        os_matches = nmap_data.get('os_matches', [])
        if os_matches:
            lines.append("**Operating System Detection:**\n\n")
            for os in os_matches[:3]:
                name = os.get('name', 'Unknown')
                accuracy = os.get('accuracy', 0)
                lines.append(f"- {name} (Accuracy: {accuracy}%)\n")
            lines.append("\n")
    else:
        lines.append("Network discovery scan not performed or no data available.\n\n")

    # 4.2 Web Application Enumeration
    lines.append("### 4.2 Web Application Enumeration\n\n")
    web_data = phases_data.get('web_enumeration', {})
    if web_data:
        discovered_paths = web_data.get('discovered_paths', [])

        if discovered_paths:
            lines.append(f"**Discovered Paths: {len(discovered_paths)}**\n\n")

            # Group by status code
            by_status = {}
            for path in discovered_paths:
                status = path.get('status', 'unknown')
                if status not in by_status:
                    by_status[status] = []
                by_status[status].append(path)

            for status, paths in sorted(by_status.items()):
                lines.append(f"**Status {status}: {len(paths)} paths**\n\n")
                lines.append("| Path | Size | Content-Type |\n")
                lines.append("|------|------|-------------|\n")

                for path in paths[:10]:  # Limit to first 10 per status
                    path_url = path.get('path', '/')
                    size = path.get('size', 'N/A')
                    content_type = path.get('content_type', 'N/A')
                    lines.append(f"| {path_url} | {size} | {content_type} |\n")

                if len(paths) > 10:
                    lines.append(f"\n*... and {len(paths) - 10} more paths.*\n")
                lines.append("\n")
        else:
            lines.append("No paths discovered or web enumeration not performed.\n\n")

        # High-risk paths
        high_risk_paths = web_data.get('high_risk_paths', [])
        if high_risk_paths:
            lines.append(f"**High-Risk Paths Identified: {len(high_risk_paths)}**\n\n")
            for path in high_risk_paths[:5]:
                lines.append(f"- `{path.get('path', 'N/A')}` - {path.get('reason', 'Sensitive path')}\n")
            lines.append("\n")
    else:
        lines.append("Web enumeration not performed or no data available.\n\n")

    # 4.3 SQL Injection Testing
    lines.append("### 4.3 SQL Injection Testing\n\n")
    sqli_data = phases_data.get('sqli_testing', {})
    if sqli_data:
        endpoints_tested = sqli_data.get('endpoints_tested', 0)
        vulnerable_endpoints = sqli_data.get('vulnerable_endpoints', 0)

        lines.append(f"**Endpoints Tested:** {endpoints_tested}\n\n")
        lines.append(f"**Vulnerable Endpoints:** {vulnerable_endpoints}\n\n")

        if vulnerable_endpoints > 0:
            sqli_results = sqli_data.get('sqli_results', [])
            lines.append("**Vulnerable Endpoints Details:**\n\n")
            lines.append("| URL | Parameter | Injection Type | Database |\n")
            lines.append("|-----|-----------|----------------|----------|\n")

            for result in sqli_results:
                if result.get('vulnerable'):
                    url = result.get('url', 'N/A')
                    param = result.get('parameter', 'N/A')
                    inj_type = result.get('injection_type', 'N/A')
                    database = result.get('database_type', 'N/A')
                    lines.append(f"| {url} | {param} | {inj_type} | {database} |\n")
            lines.append("\n")
        else:
            lines.append("✓ No SQL injection vulnerabilities found.\n\n")
    else:
        lines.append("SQL injection testing not performed or no data available.\n\n")

    # 4.4 Authentication Security Testing
    lines.append("### 4.4 Authentication Security Testing\n\n")
    auth_data = phases_data.get('authentication_testing', {})
    if auth_data:
        login_pages_tested = auth_data.get('login_pages_tested', 0)
        weak_credentials = auth_data.get('weak_credentials_found', [])

        lines.append(f"**Login Pages Tested:** {login_pages_tested}\n\n")

        if weak_credentials:
            lines.append(f"**Weak Credentials Found: {len(weak_credentials)}**\n\n")
            lines.append("| URL | Username | Issue |\n")
            lines.append("|-----|----------|-------|\n")

            for cred in weak_credentials:
                url = cred.get('url', 'N/A')
                username = cred.get('username', 'N/A')
                issue = cred.get('issue', 'Weak password')
                lines.append(f"| {url} | {username} | {issue} |\n")
            lines.append("\n")
        else:
            lines.append("✓ No weak credentials identified.\n\n")
    else:
        lines.append("Authentication testing not performed or no data available.\n\n")

    lines.append("**Note:** For complete raw tool outputs, please refer to the evidence archive (ZIP file) ")
    lines.append("included with this report.\n\n")
    lines.append("---\n\n")
    return ''.join(lines)


def _generate_recommendations_section(job: Job, db_session) -> str:
    """Generate prioritized recommendations section."""
    lines = []
    lines.append("## 5. Recommendations\n\n")
    lines.append("Based on the findings identified during this assessment, we provide the following ")
    lines.append("prioritized recommendations to improve the security posture of the system.\n\n")

    # Get findings by severity
    critical_findings = db_session.query(Finding).filter(
        Finding.job_id == job.id,
        Finding.severity == 'Critical'
    ).all()

    high_findings = db_session.query(Finding).filter(
        Finding.job_id == job.id,
        Finding.severity == 'High'
    ).all()

    medium_findings = db_session.query(Finding).filter(
        Finding.job_id == job.id,
        Finding.severity == 'Medium'
    ).all()

    # Critical priority recommendations
    if critical_findings:
        lines.append("### 5.1 Critical Priority (Immediate Action Required)\n\n")
        lines.append("The following actions should be taken **immediately** to address critical security risks:\n\n")

        for idx, finding in enumerate(critical_findings, 1):
            lines.append(f"{idx}. **{finding.title}**\n")
            if finding.remediation:
                lines.append(f"   - {finding.remediation.split(chr(10))[0]}\n")  # First line of remediation
            lines.append("\n")

    # High priority recommendations
    if high_findings:
        lines.append("### 5.2 High Priority (Address Within 30 Days)\n\n")
        lines.append("The following actions should be addressed within the next 30 days:\n\n")

        for idx, finding in enumerate(high_findings[:5], 1):  # Top 5
            lines.append(f"{idx}. **{finding.title}**\n")
            if finding.remediation:
                lines.append(f"   - {finding.remediation.split(chr(10))[0]}\n")
            lines.append("\n")

        if len(high_findings) > 5:
            lines.append(f"*... and {len(high_findings) - 5} more high-priority items. See Section 3 for details.*\n\n")

    # Medium priority recommendations
    if medium_findings:
        lines.append("### 5.3 Medium Priority (Plan for Next Security Cycle)\n\n")
        lines.append("These items should be included in the next security improvement cycle:\n\n")

        # Group by OWASP category
        by_owasp = {}
        for finding in medium_findings:
            category = finding.owasp_category or 'Other'
            if category not in by_owasp:
                by_owasp[category] = []
            by_owasp[category].append(finding)

        for category, findings in by_owasp.items():
            lines.append(f"**{category}** ({len(findings)} findings)\n")
            lines.append(f"- Review and address {len(findings)} medium-severity findings in this category\n\n")

    # General security recommendations
    lines.append("### 5.4 General Security Recommendations\n\n")
    lines.append("In addition to addressing specific findings, we recommend implementing the following ")
    lines.append("security best practices:\n\n")

    lines.append("1. **Regular Security Assessments**\n")
    lines.append("   - Conduct penetration tests quarterly or after major system changes\n")
    lines.append("   - Implement continuous vulnerability scanning\n\n")

    lines.append("2. **Patch Management**\n")
    lines.append("   - Establish a formal patch management process\n")
    lines.append("   - Subscribe to security advisories for all software components\n")
    lines.append("   - Test and deploy security patches within 30 days of release\n\n")

    lines.append("3. **Security Training**\n")
    lines.append("   - Provide security awareness training for all development team members\n")
    lines.append("   - Conduct secure coding training for developers\n")
    lines.append("   - Implement security champions program\n\n")

    lines.append("4. **Incident Response**\n")
    lines.append("   - Develop and document an incident response plan\n")
    lines.append("   - Conduct regular incident response drills\n")
    lines.append("   - Establish security monitoring and alerting\n\n")

    lines.append("5. **Security Hardening**\n")
    lines.append("   - Follow CIS Benchmarks for system hardening\n")
    lines.append("   - Implement defense-in-depth strategies\n")
    lines.append("   - Regular review and update of security configurations\n\n")

    lines.append("---\n\n")
    return ''.join(lines)


def _generate_conclusion_section(job: Job, db_session) -> str:
    """Generate conclusion section."""
    lines = []
    lines.append("## 6. Conclusion\n\n")

    # Get summary statistics
    total_findings = db_session.query(func.count(Finding.id)).filter(Finding.job_id == job.id).scalar() or 0
    severity_counts = db_session.query(
        Finding.severity,
        func.count(Finding.id)
    ).filter(Finding.job_id == job.id).group_by(Finding.severity).all()
    by_severity = {severity: count for severity, count in severity_counts}

    critical = by_severity.get('Critical', 0)
    high = by_severity.get('High', 0)
    medium = by_severity.get('Medium', 0)
    low = by_severity.get('Low', 0)

    lines.append(f"This penetration testing assessment of **{job.target}** identified **{total_findings} security findings** ")
    lines.append(f"across various categories: {critical} critical, {high} high, {medium} medium, and {low} low severity.\n\n")

    if critical > 0 or high > 0:
        lines.append("The presence of critical and/or high-severity vulnerabilities indicates that the system requires ")
        lines.append("immediate security improvements. We strongly recommend prioritizing the remediation of these findings ")
        lines.append("to reduce the risk of security breaches.\n\n")
    elif medium > 0:
        lines.append("The system demonstrates a moderate security posture with medium-severity findings that should be ")
        lines.append("addressed in the next security improvement cycle. Regular security assessments and proactive ")
        lines.append("vulnerability management will help maintain and improve security over time.\n\n")
    else:
        lines.append("The system demonstrates a good security posture. However, continuous monitoring and regular ")
        lines.append("security assessments are recommended to maintain this level of security.\n\n")

    lines.append("### Key Takeaways\n\n")

    # Get top OWASP categories
    owasp_counts = db_session.query(
        Finding.owasp_category,
        func.count(Finding.id)
    ).filter(
        Finding.job_id == job.id,
        Finding.owasp_category.isnot(None)
    ).group_by(Finding.owasp_category).order_by(func.count(Finding.id).desc()).limit(3).all()

    if owasp_counts:
        lines.append("**Primary Risk Areas (OWASP Top 10 2021):**\n\n")
        for category, count in owasp_counts:
            lines.append(f"- {category}: {count} findings\n")
        lines.append("\n")

    lines.append("**Next Steps:**\n\n")
    lines.append("1. Review all findings with your technical team\n")
    lines.append("2. Develop a remediation plan prioritized by severity\n")
    lines.append("3. Implement fixes for critical and high-severity findings immediately\n")
    lines.append("4. Schedule a re-test after remediation to verify fixes\n")
    lines.append("5. Establish ongoing security monitoring and testing\n\n")

    lines.append("This report should be treated as **confidential** and shared only with authorized personnel ")
    lines.append("involved in security remediation efforts.\n\n")

    lines.append("---\n\n")
    return ''.join(lines)


def _generate_appendix_section(phases_data: Dict[str, Any]) -> str:
    """Generate appendix section."""
    lines = []
    lines.append("## 7. Appendix\n\n")

    # 7.1 Tools and Versions
    lines.append("### 7.1 Tools and Versions\n\n")
    lines.append("The following tools were used during this assessment:\n\n")
    lines.append("| Tool | Version | Purpose |\n")
    lines.append("|------|---------|----------|\n")
    lines.append("| Nmap | 7.94+ | Network discovery and port scanning |\n")
    lines.append("| SQLMap | 1.7+ | SQL injection detection and exploitation |\n")
    lines.append("| Dirsearch | 0.4+ | Web path enumeration |\n")
    lines.append("| Hydra | 9.5+ | Authentication testing |\n")
    lines.append("| Medusa | 2.2+ | Authentication testing |\n")
    lines.append("| Python | 3.10+ | Automation and scripting |\n")
    lines.append("| Autosentou Platform | 1.0 | Test orchestration and reporting |\n\n")

    # 7.2 OWASP Top 10 2021 Reference
    lines.append("### 7.2 OWASP Top 10 2021 Reference\n\n")
    lines.append("| Category | Description |\n")
    lines.append("|----------|-------------|\n")
    lines.append("| A01:2021 | Broken Access Control |\n")
    lines.append("| A02:2021 | Cryptographic Failures |\n")
    lines.append("| A03:2021 | Injection |\n")
    lines.append("| A04:2021 | Insecure Design |\n")
    lines.append("| A05:2021 | Security Misconfiguration |\n")
    lines.append("| A06:2021 | Vulnerable and Outdated Components |\n")
    lines.append("| A07:2021 | Identification and Authentication Failures |\n")
    lines.append("| A08:2021 | Software and Data Integrity Failures |\n")
    lines.append("| A09:2021 | Security Logging and Monitoring Failures |\n")
    lines.append("| A10:2021 | Server-Side Request Forgery (SSRF) |\n\n")

    lines.append("For more information, visit: https://owasp.org/Top10/\n\n")

    # 7.3 References and Standards
    lines.append("### 7.3 References and Standards\n\n")
    lines.append("This assessment follows industry-standard methodologies and frameworks:\n\n")
    lines.append("- **OWASP Testing Guide v4.0**: https://owasp.org/www-project-web-security-testing-guide/\n")
    lines.append("- **OSSTMM (Open Source Security Testing Methodology Manual)**: https://www.isecom.org/OSSTMM.3.pdf\n")
    lines.append("- **NIST SP 800-115**: Technical Guide to Information Security Testing and Assessment\n")
    lines.append("- **CVE Database**: https://cve.mitre.org/\n")
    lines.append("- **NVD (National Vulnerability Database)**: https://nvd.nist.gov/\n")
    lines.append("- **ExploitDB**: https://www.exploit-db.com/\n\n")

    # 7.4 Evidence Archive
    lines.append("### 7.4 Evidence Archive\n\n")
    lines.append("Complete raw tool outputs and evidence are available in the evidence archive (ZIP file) ")
    lines.append("included with this report. The archive contains:\n\n")
    lines.append("- Raw Nmap scan outputs\n")
    lines.append("- SQLMap test results\n")
    lines.append("- Dirsearch enumeration results\n")
    lines.append("- Authentication testing logs\n")
    lines.append("- JSON data export of all findings\n\n")

    lines.append("---\n\n")

    # Footer
    lines.append(f"**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    lines.append(f"**Platform:** Autosentou Automated Penetration Testing Platform v1.0\n\n")
    lines.append("**End of Report**\n")

    return ''.join(lines)
