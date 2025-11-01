"""
Recommendations and Conclusion Generation

Generates overall recommendations and conclusion sections.
"""

from typing import Dict, Any
from datetime import datetime, UTC
from services.ai.ai_service import init_ai_service
from .vulnerability_utils import get_vulnerability_summary

ai_service = init_ai_service()


def generate_recommendations_section(phases_data: Dict[str, Any]) -> str:
    """
    Generate overall recommendations section based on actual findings using centralized vulnerability counts.
    Only provides specific advice if vulnerabilities are found.
    """
    lines = []

    # Get canonical vulnerability data
    vuln_summary = get_vulnerability_summary(phases_data)
    all_vulns = vuln_summary['vulnerabilities']
    stats = vuln_summary['statistics']

    # Extract additional context
    web_enum_data = phases_data.get('web_enumeration', {})
    high_risk_paths = len(web_enum_data.get('ai_rag_analysis', {}).get('high_risk_paths', []))

    # Check if there are any actual issues to address
    has_vulnerabilities = vuln_summary['has_vulnerabilities']

    if not has_vulnerabilities:
        # No vulnerabilities found - provide positive feedback
        lines.append("### Security Posture Assessment\n\n")
        lines.append("This penetration test did not identify any critical, high, or medium severity vulnerabilities in the tested scope. ")
        lines.append("The target system demonstrates a strong security posture with:\n\n")
        lines.append("- No exploitable SQL injection vulnerabilities\n")
        lines.append("- No authentication bypass or weak credential issues\n")
        lines.append("- No critical or high-severity CVE vulnerabilities detected\n")
        lines.append("- No high-risk web application paths exposing sensitive data\n\n")

        lines.append("### Ongoing Security Recommendations\n\n")
        lines.append("While no immediate vulnerabilities were found, we recommend the following ongoing security practices:\n\n")
        lines.append("**Maintain Current Security Posture**:\n")
        lines.append("- Continue regular security patch management for all services\n")
        lines.append("- Maintain current firewall and access control configurations\n")
        lines.append("- Keep security monitoring and logging systems active\n\n")

        lines.append("**Periodic Security Assessments**:\n")
        lines.append("- Schedule regular penetration tests (quarterly or semi-annually)\n")
        lines.append("- Conduct vulnerability scans on a monthly basis\n")
        lines.append("- Review and update security policies as threats evolve\n\n")

        lines.append("**Proactive Security Measures**:\n")
        lines.append("- Implement continuous security monitoring and threat intelligence\n")
        lines.append("- Conduct security awareness training for all personnel\n")
        lines.append("- Review and test incident response procedures regularly\n\n")

        return ''.join(lines)

    # Vulnerabilities were found - generate specific recommendations using AI
    # Build context about actual vulnerabilities found from canonical source
    vuln_context = []

    # Add summary statistics
    vuln_context.append(f"Total Vulnerabilities: {stats['total_vulnerabilities']}")
    vuln_context.append(f"- Critical: {stats['critical']}, High: {stats['high']}, Medium: {stats['medium']}, Low: {stats['low']}")
    vuln_context.append("")

    # Add details about critical/high vulnerabilities
    critical_high_vulns = [v for v in all_vulns if v['severity'] in ['Critical', 'High']]
    if critical_high_vulns:
        vuln_context.append(f"CRITICAL/HIGH SEVERITY VULNERABILITIES ({len(critical_high_vulns)}):")
        for vuln in critical_high_vulns[:5]:  # Top 5
            if vuln['type'] == 'cve':
                cve_id = vuln.get('cve_id', 'Unknown')
                service = vuln.get('service', 'Unknown')
                port = vuln.get('port', 'N/A')
                vuln_context.append(f"  * {cve_id} affecting {service} on port {port}")
            elif vuln['type'] == 'sqli':
                url = vuln.get('url', 'Unknown')
                vuln_context.append(f"  * SQL Injection at: {url}")
            elif vuln['type'] == 'authentication':
                url = vuln.get('url', 'Unknown')
                vuln_context.append(f"  * Account Enumeration at: {url}")
            elif vuln['type'] == 'web_exposure':
                category = vuln.get('category', 'Unknown')
                url = vuln.get('url', 'Unknown')
                vuln_context.append(f"  * {category} exposed at: {url}")
        vuln_context.append("")

    # Add details about medium/low vulnerabilities if present
    medium_low_vulns = [v for v in all_vulns if v['severity'] in ['Medium', 'Low']]
    if medium_low_vulns:
        vuln_context.append(f"MEDIUM/LOW SEVERITY VULNERABILITIES ({len(medium_low_vulns)}):")
        for vuln in medium_low_vulns[:3]:  # Top 3
            desc = vuln.get('brief_description', 'Unknown')[:80]
            vuln_context.append(f"  * {desc}")
        vuln_context.append("")

    # Add high-risk paths if present
    if high_risk_paths > 0:
        vuln_context.append(f"HIGH-RISK WEB PATHS ({high_risk_paths}):")
        for path in web_enum_data.get('ai_rag_analysis', {}).get('high_risk_paths', [])[:3]:
            vuln_context.append(f"  * {path}")

    vuln_context_text = '\n'.join(vuln_context)

    prompt = f"""
Based on this penetration test, provide SPECIFIC and ACTIONABLE security recommendations for the ACTUAL vulnerabilities found:

VULNERABILITIES IDENTIFIED:
{vuln_context_text}

IMPORTANT: Only provide recommendations that directly address the vulnerabilities listed above.
Do NOT provide generic security advice that isn't related to the actual findings.

Organize recommendations by priority:

**Critical Priority** (address immediately):
[Only include if there are critical/high severity issues. Provide specific remediation steps for each vulnerability listed above.]

**High Priority** (address within 30 days):
[Only include if there are medium severity issues. Provide specific fixes.]

**Additional Security Improvements**:
[Related improvements that would prevent similar vulnerabilities]

For each recommendation:
1. Specify WHICH vulnerability it addresses (by CVE ID, service, or URL)
2. Provide specific remediation steps
3. Expected security impact
4. Estimated effort (Low/Medium/High)

Keep recommendations focused, specific, and actionable. No generic advice.
"""

    recommendations = ai_service.generate(prompt)
    lines.append(recommendations)
    lines.append("\n")

    return ''.join(lines)


def generate_conclusion_section(phases_data: Dict[str, Any]) -> str:
    """
    Generate conclusion section using AI with centralized vulnerability statistics.
    """
    lines = []

    # Get canonical vulnerability data
    vuln_summary = get_vulnerability_summary(phases_data)
    stats = vuln_summary['statistics']

    # Get additional context
    info_data = phases_data.get('information_gathering', {})
    is_local_target = info_data.get('is_local_target', False)

    # Use centralized stats
    total_vulns = stats['total_vulnerabilities']
    critical_high = stats['critical_high']
    by_type = stats['by_type']
    
    # Generate AI conclusion
    prompt = f"""
Write a professional conclusion for a penetration testing report with the following findings:

Total Vulnerabilities: {total_vulns}
Critical/High Severity: {critical_high}
Medium/Low Severity: {stats['medium_low']}

Vulnerability Breakdown:
- CVE-based vulnerabilities: {by_type['cve']}
- SQL Injection vulnerabilities: {by_type['sqli']}
- Authentication vulnerabilities: {by_type['authentication']}
- Web exposure vulnerabilities: {by_type['web_exposure']} (sensitive files, admin panels, etc.)

Target Type: {'Internal/Private Network' if is_local_target else 'External/Public Network'}

The conclusion should:
1. Summarize the overall security posture (2-3 sentences)
2. Highlight the most critical findings requiring immediate attention
3. Emphasize the importance of ongoing security practices
4. End with next steps and follow-up recommendations

Keep it to 2-3 paragraphs. Be professional and balanced - acknowledge both issues found and any positive security measures already in place.
"""
    
    conclusion = ai_service.generate(prompt)
    lines.append(conclusion)
    lines.append("\n")
    
    # Add standard closing
    lines.append("\n---\n\n")
    lines.append("**Report prepared by**: Automated Penetration Testing System\n")
    lines.append(f"**Date**: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    lines.append("\n*This report is confidential and intended solely for the use of the organization that commissioned it.*\n")
    
    return ''.join(lines)