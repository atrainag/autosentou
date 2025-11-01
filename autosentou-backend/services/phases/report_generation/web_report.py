"""
Web Enumeration Report Generation

Generates web application testing sections with Playwright + LLM analysis.
"""

from typing import Dict, Any, Optional
from .markdown_utils import sanitize_table_cell, safe_truncate


def generate_web_enumeration_section(phases_data: Dict[str, Any]) -> Optional[str]:
    """
    Generate Web Application Testing section.
    """
    web_enum_data = phases_data.get('web_enumeration', {})

    if not web_enum_data or not web_enum_data.get('web_services_detected', True):
        return None

    lines = []

    # Directory Enumeration Summary
    lines.append("### Directory Enumeration Results\n")

    # Get path_analysis data (new structure)
    path_analysis = web_enum_data.get('path_analysis', {})
    analysis = path_analysis.get('analysis', {})
    attack_surface = web_enum_data.get('attack_surface', {})

    # Extract statistics from the new structure
    risk_summary = analysis.get('risk_summary', {})
    total_paths = analysis.get('total_paths', 0)
    all_findings = analysis.get('findings', [])

    # Calculate statistics
    critical_high_count = risk_summary.get('critical', 0) + risk_summary.get('high', 0)

    lines.append(f"- **Total Paths Discovered**: {total_paths}\n")
    lines.append(f"- **High Risk Paths**: {critical_high_count}\n")
    lines.append(f"- **Medium Risk Paths**: {risk_summary.get('medium', 0)}\n")
    lines.append(f"- **Low Risk Paths**: {risk_summary.get('low', 0)}\n")

    # Count sensitive info exposure
    sensitive_count = len([f for f in all_findings if f.get('category') in ['Sensitive File', 'info_disclosure', 'backup']])
    lines.append(f"- **Sensitive Information Exposed**: {sensitive_count}\n")
    lines.append("\n")

    # 4.2 High Risk Paths
    high_risk = [f for f in all_findings if f.get('risk') in ['critical', 'high']]
    if high_risk:
        lines.append("### 4.2 High Risk Paths\n")
        lines.append("The following paths were identified as high-risk through AI-powered analysis:\n\n")

        lines.append("| URL | Risk Level | Category | Description |\n")
        lines.append("|-----|------------|----------|-------------|\n")

        for path in high_risk[:15]:  # Top 15 high-risk paths
            url = safe_truncate(path.get('clean_path', path.get('path', 'N/A')), max_length=60, truncate_after_pipes=True)
            risk = sanitize_table_cell(path.get('risk', 'Unknown').capitalize())
            category = sanitize_table_cell(path.get('category', 'N/A'), max_length=30)
            description = safe_truncate(path.get('description', 'N/A'), max_length=50, truncate_after_pipes=True)

            lines.append(f"| {url} | {risk} | {category} | {description} |\n")

        lines.append("\n")

        # Detailed analysis for top 5
        lines.append("#### Detailed Analysis of Critical Paths\n\n")

        for idx, path in enumerate(high_risk[:5], 1):
            url = path.get('clean_path', path.get('path', 'N/A'))
            lines.append(f"##### {idx}. {url}\n\n")
            lines.append(f"**Risk Level**: {path.get('risk', 'Unknown').capitalize()}\n")
            lines.append(f"**Category**: {path.get('category', 'N/A')}\n")
            lines.append(f"**Source**: {path.get('source', 'N/A')}\n\n")

            description = path.get('description', '')
            if description:
                lines.append(f"**Description**: {description}\n\n")

            # Attack type and testing method
            attack_type = path.get('attack_type', '')
            testing_method = path.get('testing_method', '')

            if attack_type:
                lines.append(f"**Attack Type**: {attack_type}\n")
            if testing_method:
                lines.append(f"**Testing Method**: {testing_method}\n")

            if attack_type or testing_method:
                lines.append("\n")

            # Similarity score if from RAG
            if path.get('source') == 'knowledge_base':
                similarity = path.get('similarity_score', 0)
                lines.append(f"**RAG Similarity Score**: {similarity:.4f}\n\n")

    # 4.3 Sensitive Information Exposure
    sensitive_paths = [p for p in all_findings if p.get('category') in ['Sensitive File', 'info_disclosure', 'backup']]
    if sensitive_paths:
        lines.append("### 4.3 Sensitive Information Exposure\n")
        lines.append("The following paths may expose sensitive information:\n\n")

        lines.append("| URL | Category | Risk | Description |\n")
        lines.append("|-----|----------|------|-------------|\n")

        for path in sensitive_paths[:10]:
            url = safe_truncate(path.get('clean_path', path.get('path', 'N/A')), max_length=60, truncate_after_pipes=True)
            category = sanitize_table_cell(path.get('category', 'Unknown'), max_length=30)
            risk = sanitize_table_cell(path.get('risk', 'Medium').capitalize())
            description = safe_truncate(path.get('description', 'N/A'), max_length=40, truncate_after_pipes=True)

            lines.append(f"| {url} | {category} | {risk} | {description} |\n")

        lines.append("\n")

    return ''.join(lines)