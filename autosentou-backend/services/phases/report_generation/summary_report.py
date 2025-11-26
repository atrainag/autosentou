"""
Summary Report Generator
Generates a concise, high-level summary PDF report that directs users to the web dashboard for details
"""
from typing import Dict, Any
from models import Job
from datetime import datetime


def generate_summary_report(job: Job, summary_data: Dict[str, Any]) -> str:
    """
    Generate a summary-only markdown report.

    Args:
        job: Job object
        summary_data: Summary statistics from the findings table

    Returns:
        Markdown content for the summary report
    """
    lines = []

    # Header
    lines.append("# Penetration Testing Report - Executive Summary\n\n")
    if job.original_target and job.original_target != job.target:
        lines.append(f"**Target:** {job.original_target} (IP: {job.target})\n\n")
    else:
        lines.append(f"**Target:** {job.target}\n\n")
    lines.append(f"**Report Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    lines.append(f"**Job ID:** {job.id}\n\n")
    lines.append("---\n\n")

    # Executive Summary
    lines.append("## Executive Summary\n\n")
    target_display = f"{job.original_target} ({job.target})" if (job.original_target and job.original_target != job.target) else job.target
    lines.append(f"This penetration test was conducted on **{target_display}** using the Autosentou "
                "automated penetration testing platform. The assessment included:\n\n")
    lines.append("- Information Gathering and Network Reconnaissance\n")
    lines.append("- Vulnerability Analysis and CVE Detection\n")
    lines.append("- Web Application Enumeration\n")
    lines.append("- SQL Injection Testing\n")
    lines.append("- Authentication Security Testing\n\n")

    # Key Metrics
    total = summary_data.get('total_findings', 0)
    critical = summary_data.get('critical_findings', 0)
    high = summary_data.get('high_findings', 0)
    medium = summary_data.get('medium_findings', 0)
    low = summary_data.get('low_findings', 0)

    lines.append(f"The assessment identified **{total} security findings** across various categories.\n\n")

    # Findings Summary Table
    lines.append("### Findings Summary\n\n")
    lines.append("| Severity | Count | Risk Level |\n")
    lines.append("|----------|-------|------------|\n")
    lines.append(f"| Critical | {critical} | Immediate action required |\n")
    lines.append(f"| High | {high} | Prompt remediation needed |\n")
    lines.append(f"| Medium | {medium} | Address in next security cycle |\n")
    lines.append(f"| Low | {low} | Monitor and plan remediation |\n\n")

    # Risk Assessment
    lines.append("### Risk Assessment\n\n")
    if critical > 0:
        lines.append(f"**⚠️ CRITICAL RISK:** This system has {critical} critical-severity findings that "
                    "require immediate attention. These vulnerabilities could lead to complete system compromise.\n\n")
    elif high > 0:
        lines.append(f"**⚠️ HIGH RISK:** This system has {high} high-severity findings that should be "
                    "addressed promptly. These vulnerabilities could lead to significant security breaches.\n\n")
    elif medium > 0:
        lines.append(f"**⚠️ MODERATE RISK:** This system has {medium} medium-severity findings. "
                    "While not immediately exploitable, these should be addressed in the next security cycle.\n\n")
    else:
        lines.append("**✓ LOW RISK:** No critical or high severity findings were identified. "
                    "The system demonstrates good security posture.\n\n")

    # OWASP Top 10 Distribution
    owasp_categories = summary_data.get('by_owasp_category', {})
    if owasp_categories:
        lines.append("### OWASP Top 10 2021 Distribution\n\n")
        lines.append("| OWASP Category | Findings |\n")
        lines.append("|----------------|----------|\n")

        # Sort by count descending
        sorted_owasp = sorted(owasp_categories.items(), key=lambda x: x[1], reverse=True)
        for category, count in sorted_owasp[:5]:  # Top 5
            lines.append(f"| {category} | {count} |\n")
        lines.append("\n")

    # Finding Types Distribution
    finding_types = summary_data.get('by_finding_type', {})
    if finding_types:
        lines.append("### Finding Types\n\n")
        lines.append("| Type | Count |\n")
        lines.append("|------|-------|\n")

        type_names = {
            'cve': 'CVE / Outdated Components',
            'sqli': 'SQL Injection',
            'authentication': 'Authentication Issues',
            'web_exposure': 'Web Exposure / Misconfiguration'
        }

        for ftype, count in finding_types.items():
            display_name = type_names.get(ftype, ftype)
            lines.append(f"| {display_name} | {count} |\n")
        lines.append("\n")

    # Key Recommendations
    lines.append("## Key Recommendations\n\n")

    if critical > 0:
        lines.append("### Immediate Actions (Critical Priority)\n\n")
        lines.append("1. **Isolate Affected Systems:** If possible, isolate systems with critical vulnerabilities "
                    "until patches can be applied\n")
        lines.append("2. **Apply Security Patches:** Update all vulnerable components to their latest versions\n")
        lines.append("3. **Review Access Controls:** Ensure proper authentication and authorization mechanisms are in place\n\n")

    if high > 0:
        lines.append("### High Priority Actions\n\n")
        lines.append("1. **Input Validation:** Implement comprehensive input validation and sanitization\n")
        lines.append("2. **Security Headers:** Ensure all security headers are properly configured\n")
        lines.append("3. **Encryption:** Use TLS/SSL for all data in transit\n\n")

    lines.append("### General Recommendations\n\n")
    lines.append("1. **Regular Security Assessments:** Conduct penetration tests quarterly or after major changes\n")
    lines.append("2. **Security Training:** Provide security awareness training for development teams\n")
    lines.append("3. **Incident Response Plan:** Develop and test an incident response plan\n")
    lines.append("4. **Security Monitoring:** Implement continuous security monitoring and logging\n")
    lines.append("5. **Vulnerability Management:** Establish a formal vulnerability management program\n\n")

    # Call to Action - Direct to Dashboard
    lines.append("---\n\n")
    lines.append("## 📊 Interactive Detailed Report\n\n")
    lines.append("**This PDF contains only a high-level summary of findings.**\n\n")
    lines.append("For complete, detailed analysis of all vulnerabilities including:\n\n")
    lines.append("- Individual vulnerability details and proof-of-concept\n")
    lines.append("- Specific remediation guidance for each finding\n")
    lines.append("- Interactive filtering and search capabilities\n")
    lines.append("- Ability to export filtered results\n")
    lines.append("- Full technical evidence and references\n\n")
    lines.append("**Please access the interactive web dashboard:**\n\n")
    lines.append(f"```\nJob ID: {job.id}\n```\n\n")
    lines.append("Navigate to the Autosentou web application and view the interactive report dashboard "
                "for this scan to explore all findings in detail.\n\n")

    # Appendix
    lines.append("---\n\n")
    lines.append("## Appendix\n\n")
    lines.append("### Testing Methodology\n\n")
    lines.append("This assessment follows industry-standard penetration testing methodology:\n\n")
    lines.append("1. **Information Gathering** - Network reconnaissance and service identification using Nmap\n")
    lines.append("2. **Vulnerability Analysis** - CVE matching via NVD (National Vulnerability Database) API and exploit searching via ExploitDB/GitHub\n")
    lines.append("3. **Web Application Testing** - Directory enumeration using Dirsearch with AI-powered risk analysis\n")
    lines.append("4. **SQL Injection Testing** - Automated injection testing using SQLMap\n")
    lines.append("5. **Authentication Testing** - Login page security analysis and credential testing\n\n")

    lines.append("### Vulnerability Detection Sources\n\n")
    lines.append("Vulnerabilities in this report were identified through:\n\n")
    lines.append("- **NVD (National Vulnerability Database):** CVE information from NIST's official database\n")
    lines.append("- **ExploitDB:** Public exploit repository maintained by Offensive Security\n")
    lines.append("- **GitHub Security Advisories:** Open-source vulnerability disclosures and proof-of-concepts\n")
    lines.append("- **Automated Testing Tools:** SQLMap, Nmap, Dirsearch for active vulnerability testing\n\n")

    lines.append("### Severity Definitions\n\n")
    lines.append("- **Critical:** Vulnerabilities that can be exploited immediately with severe impact "
                "(e.g., remote code execution, complete system compromise)\n")
    lines.append("- **High:** Vulnerabilities that are likely exploitable and could lead to significant "
                "security breaches (e.g., SQL injection, authentication bypass)\n")
    lines.append("- **Medium:** Vulnerabilities that require specific conditions to exploit or have "
                "moderate impact (e.g., information disclosure, weak configurations)\n")
    lines.append("- **Low:** Vulnerabilities with minimal immediate risk or require significant effort "
                "to exploit (e.g., minor information leakage)\n\n")

    lines.append("### Limitations\n\n")
    lines.append("- **Automated Testing Only:** This assessment utilizes automated scanning tools. "
                "Manual penetration testing was not performed.\n")
    lines.append("- **Non-Destructive Testing:** All tests are designed to identify vulnerabilities "
                "without causing service disruption.\n")
    lines.append("- **Point-in-Time Assessment:** Results represent the security posture at the time of testing.\n\n")

    # Footer
    lines.append("---\n\n")
    lines.append(f"*Report generated by Autosentou Penetration Testing Platform on "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n")

    return ''.join(lines)
