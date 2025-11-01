"""
Executive Summary Generation

Generates AI-powered executive summary and key findings.
"""

from typing import Dict, Any
from models import Job
from services.ai.ai_service import init_ai_service
from .vulnerability_utils import get_vulnerability_summary

ai_service = init_ai_service()


def generate_executive_summary_section(job: Job, phases_data: Dict[str, Any]) -> str:
    """
    Generate executive summary section with key findings using centralized vulnerability counts.
    """
    lines = []

    # Get canonical vulnerability data
    vuln_summary = get_vulnerability_summary(phases_data)
    stats = vuln_summary['statistics']

    # Extract other data
    sqli_data = phases_data.get('sqli_testing', {})
    web_enum_data = phases_data.get('web_enumeration', {})
    info_data = phases_data.get('information_gathering', {})

    is_local_target = info_data.get('is_local_target', False)

    # Generate AI summary (no section header - handled by main generator)
    summary_text = generate_ai_executive_summary(job, phases_data, stats)
    lines.append(summary_text)
    lines.append("\n")

    # 1.1 Key Findings
    lines.append("### Key Findings\n")

    # Use canonical counts from vulnerability_utils
    lines.append(f"- **Total Vulnerabilities Identified**: {stats['total_vulnerabilities']}\n")
    lines.append(f"- **Critical/High Severity Issues**: {stats['critical_high']}\n")

    # Show breakdown by type if there are vulnerabilities
    if stats['total_vulnerabilities'] > 0:
        by_type = stats['by_type']
        type_breakdown = []
        if by_type['cve'] > 0:
            type_breakdown.append(f"{by_type['cve']} CVE-based")
        if by_type['sqli'] > 0:
            type_breakdown.append(f"{by_type['sqli']} SQL Injection")
        if by_type['authentication'] > 0:
            type_breakdown.append(f"{by_type['authentication']} Authentication")
        if by_type['web_exposure'] > 0:
            type_breakdown.append(f"{by_type['web_exposure']} Web Exposure")

        if type_breakdown:
            lines.append(f"  - Breakdown: {', '.join(type_breakdown)}\n")

    # Other metrics
    lines.append(f"- **Open Ports Discovered**: {info_data.get('nmap', {}).get('open_ports_count', 0)}\n")
    lines.append(f"- **Web Services Analyzed**: {len(web_enum_data.get('web_ports_detected', []))}\n")
    lines.append(f"- **Target Type**: {'Internal/Private Network' if is_local_target else 'External/Public Network'}\n")

    return ''.join(lines)


def generate_ai_executive_summary(job: Job, phases_data: Dict[str, Any], stats: Dict[str, Any]) -> str:
    """
    Use AI to generate executive summary text using centralized vulnerability statistics.
    """
    sqli_data = phases_data.get('sqli_testing', {})
    brute_force_data = phases_data.get('brute_force_testing', {})
    web_enum_data = phases_data.get('web_enumeration', {})
    info_data = phases_data.get('information_gathering', {})

    is_local_target = info_data.get('is_local_target', False)

    target_type = "local/private network" if is_local_target else "public/external network"

    # Use centralized stats
    total_vulns = stats['total_vulnerabilities']
    critical_high = stats['critical_high']
    by_type = stats['by_type']

    prompt = f"""
Generate an executive summary for a penetration testing report:

Target: {job.target}
Target Type: {target_type}
Total Vulnerabilities Found: {total_vulns}
Critical/High Severity: {critical_high}
Medium/Low Severity: {stats['medium_low']}

Vulnerability Breakdown:
- CVE-based vulnerabilities: {by_type['cve']}
- SQL Injection vulnerabilities: {by_type['sqli']}
- Authentication vulnerabilities: {by_type['authentication']}
- Web exposure vulnerabilities: {by_type['web_exposure']} (sensitive files, admin panels, etc.)

Additional Findings:
- Web services detected: {len(web_enum_data.get('web_ports_detected', []))}
- Open ports: {info_data.get('nmap', {}).get('open_ports_count', 0)}

{"Note: This is a local network target, so WHOIS and DNS enumeration were not performed." if is_local_target else ""}

Write a professional executive summary (3-4 paragraphs) that:
1. Provides overall security posture
2. Highlights critical findings
3. Summarizes business impact
4. Recommends priority actions

Keep it non-technical and focused on business risk.
"""

    return ai_service.generate(prompt)