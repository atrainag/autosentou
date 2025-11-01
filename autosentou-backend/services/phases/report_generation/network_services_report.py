"""
Network Services Report Generation

Generates comprehensive network services and port scan sections.
"""

from typing import Dict, Any, Optional
from .markdown_utils import sanitize_table_cell, safe_truncate


def generate_network_services_section(phases_data: Dict[str, Any]) -> str:
    """
    Generate comprehensive Network Services section with detailed port/service information.
    """
    info_data = phases_data.get('information_gathering', {})

    if not info_data:
        return ""

    lines = []
    lines.append("This section details all network services and open ports identified during reconnaissance.\n\n")

    # Get nmap data
    nmap_data = info_data.get('nmap', {})

    if not nmap_data:
        lines.append("*No network services data available.*\n")
        return ''.join(lines)

    # Summary statistics
    lines.append("### Port Scan Summary\n")
    open_ports_count = nmap_data.get('open_ports_count', 0)
    parsed_ports = nmap_data.get('parsed_ports', [])

    # Filter to only show open ports in detailed tables
    open_ports_only = [p for p in parsed_ports if p.get('state') == 'open']
    filtered_ports_count = len([p for p in parsed_ports if p.get('state') == 'filtered'])
    closed_ports_count = len([p for p in parsed_ports if p.get('state') == 'closed'])

    lines.append(f"- **Total Open Ports**: {open_ports_count}\n")
    lines.append(f"- **Services Identified**: {len(open_ports_only)}\n")
    if filtered_ports_count > 0:
        lines.append(f"- **Filtered Ports**: {filtered_ports_count} (firewall blocking)\n")
    if closed_ports_count > 0:
        lines.append(f"- **Closed Ports**: {closed_ports_count}\n")
    lines.append(f"- **Scan Type**: TCP Connect scan with service version detection\n")

    # Get unique services (only from open ports)
    unique_services = set()
    for port in open_ports_only:
        service = port.get('service', 'Unknown')
        if service and service.lower() != 'unknown':
            unique_services.add(service)

    lines.append(f"- **Unique Services**: {len(unique_services)}\n\n")

    # OS Detection Information (if available)
    os_info = nmap_data.get('os_detection', {})
    if os_info and not os_info.get('skipped'):
        lines.append("### Operating System Detection\n")

        os_matches = os_info.get('os_matches', [])
        if os_matches:
            lines.append("**Detected Operating Systems** (by confidence):\n\n")
            lines.append("| OS Name | Accuracy | Type |\n")
            lines.append("|---------|----------|------|\n")

            for os_match in os_matches[:5]:  # Top 5 matches
                os_name = sanitize_table_cell(os_match.get('name', 'Unknown'), max_length=50)
                accuracy = sanitize_table_cell(os_match.get('accuracy', 'N/A'))
                os_type = sanitize_table_cell(os_match.get('type', 'N/A'))
                lines.append(f"| {os_name} | {accuracy}% | {os_type} |\n")

            lines.append("\n")

        # OS Classes
        os_classes = os_info.get('os_classes', [])
        if os_classes:
            lines.append("**Operating System Classes**:\n\n")
            for os_class in os_classes[:3]:
                vendor = os_class.get('vendor', 'Unknown')
                os_family = os_class.get('osfamily', 'Unknown')
                os_gen = os_class.get('osgen', '')
                accuracy = os_class.get('accuracy', 'N/A')
                lines.append(f"- {vendor} {os_family} {os_gen} (Accuracy: {accuracy}%)\n")
            lines.append("\n")

    # Detailed Port/Service Table
    if open_ports_only:
        lines.append("### Detailed Port and Service Information\n")
        lines.append("The following table lists all open ports and their associated services:\n\n")

        lines.append("| Port | Protocol | State | Service | Version | Additional Info |\n")
        lines.append("|------|----------|-------|---------|---------|------------------|\n")

        # Sort ports numerically (only show open ports)
        sorted_ports = sorted(open_ports_only, key=lambda x: x.get('port', 0))

        for port in sorted_ports:
            port_num = sanitize_table_cell(port.get('port', 'N/A'))
            proto = sanitize_table_cell(port.get('proto', 'tcp'))
            state = sanitize_table_cell(port.get('state', 'Unknown'))
            service = sanitize_table_cell(port.get('service', 'Unknown'))

            # Sanitize and truncate version (remove content after pipes first)
            version = safe_truncate(port.get('version', ''), max_length=30, truncate_after_pipes=True)
            if not version:
                version = ''

            # Sanitize and truncate extra_info (remove content after pipes first)
            extra_info = safe_truncate(port.get('extra_info', ''), max_length=50, truncate_after_pipes=True)

            lines.append(f"| {port_num} | {proto} | {state} | {service} | {version} | {extra_info} |\n")

        lines.append("\n")

        # Categorize services by type
        lines.append("### Services by Category\n")

        # Categorization
        web_services = []
        database_services = []
        remote_access_services = []
        email_services = []
        file_transfer_services = []
        other_services = []

        for port in sorted_ports:
            service = port.get('service', '').lower()
            port_num = port.get('port')
            version = port.get('version', 'N/A')

            service_info = f"Port {port_num}: {service} {version}"

            if any(web in service for web in ['http', 'https', 'web', 'apache', 'nginx', 'iis']):
                web_services.append(service_info)
            elif any(db in service for db in ['mysql', 'postgresql', 'mssql', 'mongodb', 'redis', 'oracle', 'db']):
                database_services.append(service_info)
            elif any(remote in service for remote in ['ssh', 'telnet', 'rdp', 'vnc', 'ftp']):
                remote_access_services.append(service_info)
            elif any(mail in service for mail in ['smtp', 'pop3', 'imap', 'mail']):
                email_services.append(service_info)
            elif any(ft in service for ft in ['ftp', 'sftp', 'tftp', 'smb', 'nfs']):
                file_transfer_services.append(service_info)
            else:
                other_services.append(service_info)

        # Display categorized services
        if web_services:
            lines.append("**Web Services**:\n")
            for svc in web_services:
                lines.append(f"- {svc}\n")
            lines.append("\n")

        if database_services:
            lines.append("**Database Services**:\n")
            for svc in database_services:
                lines.append(f"- {svc}\n")
            lines.append("\n")

        if remote_access_services:
            lines.append("**Remote Access Services**:\n")
            for svc in remote_access_services:
                lines.append(f"- {svc}\n")
            lines.append("\n")

        if email_services:
            lines.append("**Email Services**:\n")
            for svc in email_services:
                lines.append(f"- {svc}\n")
            lines.append("\n")

        if file_transfer_services:
            lines.append("**File Transfer Services**:\n")
            for svc in file_transfer_services:
                lines.append(f"- {svc}\n")
            lines.append("\n")

        if other_services:
            lines.append("**Other Services**:\n")
            for svc in other_services:
                lines.append(f"- {svc}\n")
            lines.append("\n")

    # Security Implications
    lines.append("### Security Implications\n")

    # Analyze for common security concerns (only check open ports)
    # Use a set to track which warnings we've already added (avoid duplicates)
    security_concerns = []
    added_warnings = set()

    for port in open_ports_only:
        port_num = port.get('port', 0)
        service = port.get('service', '').lower()

        # Check for insecure services (use warning keys to prevent duplicates)
        if 'telnet' in service and 'telnet' not in added_warnings:
            security_concerns.append("[!] **Telnet (Port 23)**: Transmits credentials in plaintext. Should be replaced with SSH.")
            added_warnings.add('telnet')
        elif 'ftp' in service and port_num == 21 and 'ftp' not in added_warnings:
            security_concerns.append("[!] **FTP (Port 21)**: Transmits credentials in plaintext. Consider using SFTP or FTPS.")
            added_warnings.add('ftp')
        elif service == 'http' and port_num == 80 and 'http' not in added_warnings:
            security_concerns.append("[i] **HTTP (Port 80)**: Unencrypted web traffic. Consider implementing HTTPS.")
            added_warnings.add('http')
        elif ('smb' in service or port_num in [139, 445]) and 'smb' not in added_warnings:
            security_concerns.append("[!] **SMB (Ports 139/445)**: Commonly targeted for lateral movement. Ensure proper access controls.")
            added_warnings.add('smb')
        elif ('rdp' in service or port_num == 3389) and 'rdp' not in added_warnings:
            security_concerns.append("[!] **RDP (Port 3389)**: Commonly targeted for brute force attacks. Implement strong authentication and rate limiting.")
            added_warnings.add('rdp')
        elif port_num in [3306, 5432, 1433, 27017]:
            # For database services, create a unique key per port
            db_key = f'db_{port_num}'
            if db_key not in added_warnings:
                security_concerns.append(f"[!] **Database Service (Port {port_num})**: Should not be exposed to public internet. Implement network segmentation.")
                added_warnings.add(db_key)

    if security_concerns:
        lines.append("The following security considerations were identified based on the discovered services:\n\n")
        for concern in security_concerns:
            lines.append(f"{concern}\n\n")
    else:
        lines.append("No obvious security concerns were identified with the exposed services. However, all services should be kept updated and properly configured.\n\n")

    return ''.join(lines)
