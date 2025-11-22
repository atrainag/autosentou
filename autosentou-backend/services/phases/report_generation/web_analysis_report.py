"""
Web Analysis Report Generation (Phase 3)

Generates detailed findings from Playwright + LLM analysis.
This is the main technical findings section organized by OWASP Top 10 2021.
"""

import os
import base64
from typing import Dict, Any, List, Optional
from collections import defaultdict


def _get_screenshot_base64(screenshot_path: Optional[str]) -> Optional[str]:
    """
    Convert screenshot image to base64 for embedding in HTML/PDF.

    Args:
        screenshot_path: Path to screenshot image file

    Returns:
        Base64-encoded image string or None if file doesn't exist
    """
    if not screenshot_path or not os.path.exists(screenshot_path):
        return None

    try:
        with open(screenshot_path, 'rb') as f:
            img_data = f.read()
            base64_img = base64.b64encode(img_data).decode('utf-8')
            return f"data:image/png;base64,{base64_img}"
    except Exception as e:
        print(f"Warning: Failed to encode screenshot {screenshot_path}: {e}")
        return None


def generate_web_analysis_section(phases_data: Dict[str, Any]) -> str:
    """
    Generate Phase 3: Web Analysis section with OWASP-categorized findings.

    This is the main technical findings section of the report.
    Findings are organized by OWASP Top 10 2021 category and risk level.
    """
    web_analysis_data = phases_data.get('web_analysis', {})

    if not web_analysis_data or not web_analysis_data.get('analysis_results'):
        return ""

    lines = []
    lines.append("## 3.3 Phase 3: Web Analysis\n\n")
    lines.append("### Overview\n\n")
    lines.append("Deep analysis of discovered web paths using Playwright browser automation and LLM-powered security analysis.\n")
    lines.append(f"**Pages Analyzed**: {web_analysis_data.get('pages_analyzed', 0)}\n")
    lines.append(f"**Response Groups**: {web_analysis_data.get('response_groups_count', 0)}\n\n")

    # Extract all findings
    all_findings = []
    for analysis in web_analysis_data.get('analysis_results', []):
        for finding in analysis.get('findings', []):
            all_findings.append({
                **finding,
                'url': analysis.get('url', ''),
                'page_type': analysis.get('page_type', '')
            })

    if not all_findings:
        lines.append("**No security vulnerabilities detected during web analysis.**\n\n")
        return ''.join(lines)

    # Group findings by OWASP category and risk level
    findings_by_owasp = defaultdict(lambda: {'High': [], 'Medium': [], 'Low': []})

    for finding in all_findings:
        category = finding.get('owasp_category', 'Unknown')
        risk = finding.get('risk_level', 'Low')
        findings_by_owasp[category][risk].append(finding)

    # Generate findings by OWASP category (sorted by count)
    category_counts = [(cat, sum(len(findings_by_owasp[cat][r]) for r in ['High', 'Medium', 'Low']))
                       for cat in findings_by_owasp.keys()]
    sorted_categories = sorted(category_counts, key=lambda x: x[1], reverse=True)

    lines.append("### Detailed Findings by OWASP Category\n\n")

    for cat_idx, (owasp_category, count) in enumerate(sorted_categories, 1):
        lines.append(f"#### {cat_idx}. {owasp_category}\n\n")

        category_findings = findings_by_owasp[owasp_category]

        # Show findings by risk level (High → Medium → Low)
        for risk_level in ['High', 'Medium', 'Low']:
            risk_findings = category_findings[risk_level]

            if not risk_findings:
                continue

            lines.append(f"##### {risk_level} Risk Findings ({len(risk_findings)})\n\n")

            for finding_idx, finding in enumerate(risk_findings, 1):
                lines.append(_format_finding(finding, finding_idx))

        lines.append("\n---\n\n")

    return ''.join(lines)


def _format_finding(finding: Dict[str, Any], index: int) -> str:
    """Format a single finding in professional pentest report style."""
    lines = []

    # Finding header
    title = finding.get('title', finding.get('vector', 'Security Finding'))
    finding_id = finding.get('id', f'finding-{index}')

    lines.append(f"**Finding #{index}: {title}** (`{finding_id}`)\n\n")

    # Core Information
    lines.append(f"- **Risk Level**: {finding.get('risk_level', 'Unknown')}\n")
    lines.append(f"- **OWASP Category**: {finding.get('owasp_category', 'Unknown')}\n")
    lines.append(f"- **Vector**: {finding.get('vector', 'N/A')}\n")

    # Affected URL
    url = finding.get('url', '')
    affected_urls = finding.get('affected_urls', [url] if url else [])
    if affected_urls:
        lines.append(f"- **Affected URL(s)**:\n")
        for affected_url in affected_urls[:5]:  # Limit to 5 URLs
            lines.append(f"  - {affected_url}\n")

    lines.append("\n")

    # Description
    description = finding.get('description', '')
    if description:
        lines.append(f"**Description:**\n\n{description}\n\n")

    # Evidence
    evidence = finding.get('evidence', '')
    if evidence:
        lines.append(f"**Evidence:**\n\n```\n{evidence}\n```\n\n")

    # Screenshot
    screenshot_path = finding.get('screenshot_path')
    if screenshot_path:
        screenshot_base64 = _get_screenshot_base64(screenshot_path)
        if screenshot_base64:
            lines.append(f"**Page Screenshot:**\n\n")
            lines.append(f'<img src="{screenshot_base64}" alt="Page Screenshot" style="max-width: 100%; border: 1px solid #ccc; margin: 10px 0;" />\n\n')

    # Attack Details
    method = finding.get('method', '')
    parameters = finding.get('parameters', [])
    payloads = finding.get('payload', [])

    if method or parameters or payloads:
        lines.append(f"**Attack Details:**\n\n")

        if method:
            lines.append(f"- **HTTP Method**: {method}\n")

        if parameters:
            params_str = ', '.join(parameters[:10])  # Limit to 10 params
            lines.append(f"- **Parameters**: {params_str}\n")

        if payloads:
            lines.append(f"- **Example Payloads**:\n")
            for payload in payloads[:5]:  # Limit to 5 payloads
                lines.append(f"  - `{payload}`\n")

        lines.append("\n")

    # Remediation
    remediation = finding.get('remediation', '')
    if remediation:
        lines.append(f"**Remediation:**\n\n{remediation}\n\n")

    # Related Endpoints
    related_endpoints = finding.get('related_endpoints', [])
    if related_endpoints:
        lines.append(f"**Related Endpoints**: {', '.join(related_endpoints[:5])}\n\n")

    return ''.join(lines)


def generate_web_analysis_summary_table(phases_data: Dict[str, Any]) -> str:
    """Generate summary table for web analysis findings."""
    web_analysis_data = phases_data.get('web_analysis', {})

    if not web_analysis_data:
        return ""

    all_findings = []
    for analysis in web_analysis_data.get('analysis_results', []):
        for finding in analysis.get('findings', []):
            all_findings.append(finding)

    if not all_findings:
        return ""

    # Group by risk level
    high = len([f for f in all_findings if f.get('risk_level') == 'High'])
    medium = len([f for f in all_findings if f.get('risk_level') == 'Medium'])
    low = len([f for f in all_findings if f.get('risk_level') == 'Low'])

    lines = []
    lines.append("**Table: Web Analysis Findings Summary**\n\n")
    lines.append("| Risk Level | Count |\n")
    lines.append("|-----------|-------|\n")
    lines.append(f"| High | {high} |\n")
    lines.append(f"| Medium | {medium} |\n")
    lines.append(f"| Low | {low} |\n")
    lines.append(f"| **Total** | **{high + medium + low}** |\n\n")

    return ''.join(lines)
