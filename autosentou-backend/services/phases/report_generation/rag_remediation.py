"""
RAG-Powered Remediation Suggestions
Uses the exploit knowledge base to provide intelligent, context-aware remediation guidance.
"""
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)


def get_smart_remediation(finding_data: Dict[str, Any]) -> Dict[str, str]:
    """
    Get smart remediation suggestions using RAG service.

    Args:
        finding_data: Dictionary containing finding information (CVE, service, version, etc.)

    Returns:
        Dictionary with enhanced remediation info
    """
    try:
        from services.ai.rag_service import init_exploit_rag_service

        rag_service = init_exploit_rag_service()

        # Extract relevant information
        cve_id = finding_data.get('cve_id')
        service = finding_data.get('service', '')
        version = finding_data.get('version', '')
        severity = finding_data.get('severity', '')

        if not service:
            return {
                'remediation': 'Update the affected component to the latest version.',
                'references': [],
                'exploit_available': False
            }

        # Query RAG for matching exploits
        exploits = rag_service.find_matching_exploits(
            service=service,
            version=version,
            n_results=3
        )

        if exploits:
            # Use the best matching exploit data
            best_match = exploits[0]

            remediation_steps = _generate_remediation_from_exploit(best_match, service, version)
            references = best_match.get('exploit_urls', [])

            if cve_id and cve_id == best_match.get('cve_id'):
                references.insert(0, f"https://nvd.nist.gov/vuln/detail/{cve_id}")

            return {
                'remediation': remediation_steps,
                'references': references,
                'exploit_available': best_match.get('poc_available', False),
                'exploit_complexity': best_match.get('attack_complexity', 'unknown'),
                'requires_auth': best_match.get('requires_auth', False)
            }
        else:
            # Fallback to generic remediation
            return _generate_generic_remediation(finding_data)

    except Exception as e:
        logger.warning(f"RAG service not available or error occurred: {e}")
        return _generate_generic_remediation(finding_data)


def _generate_remediation_from_exploit(exploit: Dict[str, Any], service: str, version: str) -> str:
    """Generate detailed remediation steps based on exploit data."""
    lines = []

    # Severity-based urgency
    severity = exploit.get('severity', 'unknown')
    if severity in ['critical', 'high']:
        lines.append("**URGENT ACTION REQUIRED**\n\n")

    # Main remediation
    cve_id = exploit.get('cve_id', '')
    lines.append(f"This vulnerability ({cve_id}) affects {service} {version}. ")

    # Specific patch information
    if 'Apache' in service:
        lines.append("To remediate:\n\n")
        lines.append("1. **Immediate Action**: Update Apache HTTP Server to the latest stable version\n")
        lines.append("   - Download from: https://httpd.apache.org/download.cgi\n")
        lines.append("   - For RHEL/CentOS: `yum update httpd`\n")
        lines.append("   - For Debian/Ubuntu: `apt-get update && apt-get upgrade apache2`\n\n")
        lines.append("2. **Verify Configuration**: Review and update Apache configuration files\n")
        lines.append("   - Disable unnecessary modules\n")
        lines.append("   - Review security-related directives\n\n")
        lines.append("3. **Test**: Verify the update doesn't break functionality\n")
        lines.append("4. **Monitor**: Watch for unusual access patterns in logs\n")

    elif 'MySQL' in service or 'MariaDB' in service:
        lines.append("To remediate:\n\n")
        lines.append("1. **Immediate Action**: Update MySQL/MariaDB to the latest version\n")
        lines.append("   - MySQL: https://dev.mysql.com/downloads/\n")
        lines.append("   - MariaDB: https://mariadb.org/download/\n\n")
        lines.append("2. **Security Hardening**:\n")
        lines.append("   - Run `mysql_secure_installation`\n")
        lines.append("   - Review user privileges and remove unnecessary accounts\n")
        lines.append("   - Ensure `local_infile` is disabled\n\n")
        lines.append("3. **Network Security**: Restrict database access to trusted IPs only\n")

    elif 'nginx' in service.lower():
        lines.append("To remediate:\n\n")
        lines.append("1. **Immediate Action**: Update nginx to the latest stable version\n")
        lines.append("   - For RHEL/CentOS: `yum update nginx`\n")
        lines.append("   - For Debian/Ubuntu: `apt-get update && apt-get upgrade nginx`\n\n")
        lines.append("2. **Configuration Review**: Check nginx.conf for security best practices\n")
        lines.append("3. **SSL/TLS**: Ensure modern TLS protocols are used (TLS 1.2+)\n")

    elif 'SSH' in service or 'OpenSSH' in service:
        lines.append("To remediate:\n\n")
        lines.append("1. **Immediate Action**: Update OpenSSH to version 7.8 or later\n")
        lines.append("   - For RHEL/CentOS: `yum update openssh-server`\n")
        lines.append("   - For Debian/Ubuntu: `apt-get update && apt-get upgrade openssh-server`\n\n")
        lines.append("2. **Hardening**:\n")
        lines.append("   - Disable root login: `PermitRootLogin no`\n")
        lines.append("   - Use key-based authentication\n")
        lines.append("   - Implement fail2ban or similar brute-force protection\n")

    elif 'SMB' in service or 'Samba' in service:
        lines.append("To remediate:\n\n")
        lines.append("1. **CRITICAL**: Apply MS17-010 patch immediately\n")
        lines.append("   - Windows Update should be run\n")
        lines.append("   - Alternatively, disable SMBv1: `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`\n\n")
        lines.append("2. **Network Segmentation**: Isolate file servers from internet exposure\n")
        lines.append("3. **Monitoring**: Enable advanced threat protection and monitor SMB traffic\n")

    elif 'Tomcat' in service:
        lines.append("To remediate:\n\n")
        lines.append("1. **Immediate Action**: Update Apache Tomcat to the latest version\n")
        lines.append("   - Download from: https://tomcat.apache.org/download-90.cgi\n\n")
        lines.append("2. **Disable AJP Connector** if not needed:\n")
        lines.append("   - Comment out AJP connector in `server.xml`\n")
        lines.append("   - If needed, restrict AJP to localhost only\n\n")
        lines.append("3. **Security Manager**: Enable Tomcat's security manager for additional protection\n")

    else:
        # Generic remediation
        lines.append("To remediate:\n\n")
        lines.append(f"1. **Immediate Action**: Update {service} to the latest stable version\n")
        lines.append("   - Check vendor website for security patches\n")
        lines.append("   - Review security advisories\n\n")
        lines.append("2. **Configuration Review**: Follow vendor security hardening guidelines\n")
        lines.append("3. **Network Security**: Implement defense-in-depth controls\n")

    # Additional context
    if exploit.get('requires_auth'):
        lines.append("\n**Note**: This exploit requires authentication, but weak credentials could enable exploitation.\n")

    attack_complexity = exploit.get('attack_complexity', '')
    if attack_complexity == 'low':
        lines.append("\n**Warning**: This vulnerability is easily exploitable with low attack complexity.\n")

    return ''.join(lines)


def _generate_generic_remediation(finding_data: Dict[str, Any]) -> Dict[str, str]:
    """Generate generic remediation when RAG data is not available."""
    finding_type = finding_data.get('finding_type', '')
    severity = finding_data.get('severity', '')

    remediation = ""

    if finding_type == 'cve':
        remediation = (
            "1. **Update Software**: Update the affected component to the latest version\n"
            "   - Check vendor security advisories\n"
            "   - Test updates in a staging environment first\n\n"
            "2. **Workarounds**: If immediate patching is not possible:\n"
            "   - Implement network-level controls (firewall rules, ACLs)\n"
            "   - Disable affected features if not critical\n"
            "   - Increase monitoring for exploitation attempts\n\n"
            "3. **Verification**: After patching, re-scan to confirm remediation\n"
        )

    elif finding_type == 'sqli':
        remediation = (
            "1. **Immediate Fix**: Implement parameterized queries/prepared statements\n"
            "   - Never concatenate user input into SQL queries\n"
            "   - Use ORM frameworks when possible\n\n"
            "2. **Input Validation**: Implement strict input validation\n"
            "   - Whitelist allowed characters\n"
            "   - Validate data types and formats\n\n"
            "3. **Least Privilege**: Ensure database accounts have minimal required permissions\n"
            "4. **WAF**: Deploy a Web Application Firewall to detect/block SQL injection attempts\n"
        )

    elif finding_type == 'authentication':
        remediation = (
            "1. **Password Policy**: Enforce strong password requirements\n"
            "   - Minimum 12 characters\n"
            "   - Complexity requirements (uppercase, lowercase, numbers, symbols)\n"
            "   - Password expiration and history\n\n"
            "2. **Multi-Factor Authentication**: Implement MFA for all user accounts\n"
            "3. **Account Lockout**: Implement account lockout after failed login attempts\n"
            "4. **Session Management**: Use secure session tokens and implement proper timeout\n"
        )

    elif finding_type == 'web_exposure':
        remediation = (
            "1. **Access Control**: Implement proper authentication and authorization\n"
            "   - Require authentication for sensitive paths\n"
            "   - Use role-based access control (RBAC)\n\n"
            "2. **Directory Listing**: Disable directory browsing\n"
            "   - Apache: `Options -Indexes`\n"
            "   - nginx: `autoindex off;`\n\n"
            "3. **Sensitive Files**: Remove or restrict access to:\n"
            "   - Configuration files\n"
            "   - Backup files\n"
            "   - Development/debugging files\n\n"
            "4. **Security Headers**: Implement security headers (X-Frame-Options, CSP, etc.)\n"
        )

    else:
        remediation = (
            "1. **Review Finding**: Analyze the specific vulnerability details\n"
            "2. **Apply Fix**: Implement vendor-recommended remediation steps\n"
            "3. **Test**: Verify the fix doesn't impact functionality\n"
            "4. **Re-scan**: Confirm the vulnerability is resolved\n"
        )

    references = []
    if finding_data.get('cve_id'):
        references.append(f"https://nvd.nist.gov/vuln/detail/{finding_data['cve_id']}")
    if finding_data.get('owasp_category'):
        references.append("https://owasp.org/Top10/")

    return {
        'remediation': remediation,
        'references': references,
        'exploit_available': False
    }


def enhance_finding_with_rag(finding: Any) -> None:
    """
    Enhance a Finding object with RAG-powered remediation.

    Args:
        finding: Finding model object (will be modified in place)
    """
    finding_data = {
        'cve_id': finding.cve_id,
        'service': finding.service,
        'version': finding.service,  # Service field may contain version info
        'severity': finding.severity,
        'finding_type': finding.finding_type,
        'owasp_category': finding.owasp_category
    }

    smart_remediation = get_smart_remediation(finding_data)

    # Update finding with enhanced remediation
    if not finding.remediation or len(finding.remediation) < 100:
        finding.remediation = smart_remediation.get('remediation', finding.remediation)

    # Add references to evidence JSON if not present
    if smart_remediation.get('references'):
        import json

        # Initialize evidence as dict if it's None
        if finding.evidence is None:
            finding.evidence = {}
        elif not isinstance(finding.evidence, dict):
            finding.evidence = {}

        # Get existing references from evidence
        existing_refs = finding.evidence.get('references', [])
        if not isinstance(existing_refs, list):
            existing_refs = []

        # Merge references
        all_refs = list(set(existing_refs + smart_remediation['references']))
        finding.evidence['references'] = all_refs

    # Add exploit metadata to impact in evidence JSON if available
    if smart_remediation.get('exploit_available'):
        exploit_info = f"\n\n**Exploit Status**: Public exploit available. "
        if smart_remediation.get('attack_complexity') == 'low':
            exploit_info += "Low attack complexity - easily exploitable."
        elif smart_remediation.get('attack_complexity') == 'high':
            exploit_info += "High attack complexity - exploitation requires specific conditions."

        # Initialize evidence as dict if needed
        if finding.evidence is None:
            finding.evidence = {}
        elif not isinstance(finding.evidence, dict):
            finding.evidence = {}

        # Store impact in evidence JSON
        current_impact = finding.evidence.get('impact', '')
        if current_impact:
            finding.evidence['impact'] = current_impact + exploit_info
        else:
            # Generate basic impact statement
            if finding.severity == 'Critical':
                base_impact = "This critical vulnerability could lead to complete system compromise."
            elif finding.severity == 'High':
                base_impact = "This high-severity vulnerability could lead to significant security breaches."
            elif finding.severity == 'Medium':
                base_impact = "This vulnerability could be exploited under specific conditions."
            else:
                base_impact = "This vulnerability has security implications."

            finding.evidence['impact'] = base_impact + exploit_info
