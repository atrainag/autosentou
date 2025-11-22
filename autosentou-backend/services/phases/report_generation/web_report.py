"""
Web Enumeration Report Generation (Phase 2)

Simple path discovery report - NO AI classification based on path names.
All vulnerability analysis is done in Phase 3 (Web Analysis) with Playwright + LLM.
"""

from typing import Dict, Any, Optional
from .markdown_utils import sanitize_table_cell


def generate_web_enumeration_section(phases_data: Dict[str, Any]) -> Optional[str]:
    """
    Generate Phase 2: Web Enumeration section.

    This section ONLY lists discovered paths - no AI classification.
    Actual vulnerability analysis happens in Phase 3 (Web Analysis).
    """
    web_enum_data = phases_data.get('web_enumeration', {})

    if not web_enum_data or not web_enum_data.get('web_services_detected', True):
        return None

    lines = []

    lines.append("## 3.2 Phase 2: Web Enumeration\n\n")
    lines.append("### Overview\n\n")
    lines.append("Directory and path discovery using feroxbuster and gospider.\n\n")

    # Get discovered paths
    discovered_paths = web_enum_data.get('discovered_paths', [])

    # Get statistics
    total_paths = len(discovered_paths)
    web_ports = web_enum_data.get('web_ports_detected', [])

    lines.append(f"- **Web Services Found**: {len(web_ports)}\n")
    lines.append(f"- **Total Paths Discovered**: {total_paths}\n")
    lines.append("\n")

    # Show discovered paths in a simple table
    if discovered_paths:
        lines.append("### Discovered Paths\n\n")
        lines.append("The following paths were discovered and will be analyzed in Phase 3 (Web Analysis):\n\n")

        lines.append("| # | URL | Status | Source |\n")
        lines.append("|---|-----|--------|--------|\n")

        # Show up to 100 paths
        for idx, path_info in enumerate(discovered_paths[:100], 1):
            url = path_info.get('url', path_info.get('path', 'N/A'))
            status = path_info.get('status_code', path_info.get('status', 'N/A'))
            source = path_info.get('source', 'feroxbuster')

            # Sanitize for table
            url_clean = sanitize_table_cell(url, max_length=80)

            lines.append(f"| {idx} | {url_clean} | {status} | {source} |\n")

        if total_paths > 100:
            lines.append(f"\n*({total_paths - 100} additional paths discovered - see full list in appendix)*\n")

        lines.append("\n")

    # Show web ports detected
    if web_ports:
        lines.append("### Web Services Detected\n\n")
        lines.append("The following HTTP/HTTPS services were detected:\n\n")

        # web_ports is a list of integers [80, 443, 8080]
        ports_list = ', '.join([str(port) for port in web_ports])
        lines.append(f"**Ports**: {ports_list}\n\n")

    lines.append("**Note**: Path vulnerability analysis is performed in Phase 3 (Web Analysis) using ")
    lines.append("Playwright browser automation and LLM-powered content analysis.\n\n")

    return ''.join(lines)
