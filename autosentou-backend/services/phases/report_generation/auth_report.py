"""
Authentication Security Report Generation

Generates authentication testing sections focused on:
- Username enumeration vulnerabilities (OWASP A04:2021)
- Login response analysis
- Security control recommendations

Does NOT include brute-force attack results.
"""

from typing import Dict, Any, Optional
from .markdown_utils import sanitize_table_cell, safe_truncate


def generate_auth_section(phases_data: Dict[str, Any]) -> Optional[str]:
    """
    Generate Authentication Security Testing section.

    Focuses on username enumeration and login security analysis.
    """
    # Check both new and old keys for backward compatibility
    auth_data = phases_data.get('authentication_testing') or phases_data.get('brute_force_testing', {})

    if not auth_data or auth_data.get('login_pages_tested', 0) == 0:
        return None

    lines = []

    # Testing type
    testing_type = auth_data.get('testing_type', 'Authentication Security Analysis (Username Enumeration Detection)')
    lines.append(f"**Testing Type**: {testing_type}\n\n")

    # Summary
    login_pages = auth_data.get('login_pages_tested', 0)
    vulnerable_responses = auth_data.get('vulnerable_login_pages', auth_data.get('vulnerable_login_responses', 0))

    lines.append(f"**Login Pages Tested**: {login_pages}\n")
    lines.append(f"**Vulnerable Login Pages**: {vulnerable_responses}\n")

    # Security summary
    sec_summary = auth_data.get('security_summary', {})
    if sec_summary:
        secure_count = sec_summary.get('secure_implementations', login_pages - vulnerable_responses)
        lines.append(f"**Secure Implementations**: {secure_count}\n\n")

    # Note about testing methodology
    note = auth_data.get('note')
    if note:
        lines.append(f"> **Note**: {note}\n\n")

    if vulnerable_responses == 0:
        lines.append("[+] **No username enumeration vulnerabilities were found. All tested login pages use generic error messages.**\n\n")
        return ''.join(lines)

    # 6.1 Login Page Analysis
    login_tests = auth_data.get('login_response_tests', [])

    if login_tests:
        lines.append("### 6.1 Login Page Security Analysis\n\n")

        # Summary table
        lines.append("| URL | Username Enumeration | Risk Level | Status |\n")
        lines.append("|-----|----------------------|------------|--------|\n")

        for test in login_tests:
            url = safe_truncate(test.get('url', 'N/A'), max_length=60, truncate_after_pipes=True)
            ai_analysis = test.get('ai_analysis', {})

            enum_possible = ai_analysis.get('account_enumeration_possible')
            risk = ai_analysis.get('risk_level', 'Unknown')

            # Use ASCII indicators instead of emoji
            enum_status = "[!] Vulnerable" if enum_possible else "[+] Secure"
            risk_indicator = "[!!]" if risk == "High" else "[!]" if risk == "Medium" else "[.]" if risk == "Low" else "[?]"
            risk_safe = sanitize_table_cell(f"{risk_indicator} {risk}")

            lines.append(f"| {url} | {enum_status} | {risk_safe} | {'FAIL' if enum_possible else 'PASS'} |\n")

        lines.append("\n")

        # Detailed findings - only for vulnerable pages
        vulnerable_tests = [t for t in login_tests if t.get('ai_analysis', {}).get('account_enumeration_possible')]

        if vulnerable_tests:
            lines.append("### 6.2 Detailed Vulnerability Findings\n\n")

            for idx, test in enumerate(vulnerable_tests, 1):
                ai_analysis = test.get('ai_analysis', {})

                vuln_id = f"VULN-AUTH-{idx:03d}"

                lines.append(f"#### {vuln_id}: {test.get('url', 'N/A')}\n\n")

                # Classification
                classification = ai_analysis.get('classification', {})
                owasp_cat = classification.get('owasp', "A04:2021 – Insecure Design")
                severity = classification.get('severity', 'Low')
                cwe = classification.get('cwe', 'CWE-204: Observable Response Discrepancy')

                lines.append(f"**OWASP Category**: {owasp_cat}\n")
                lines.append(f"**CWE**: {cwe}\n")
                lines.append(f"**Severity**: {severity}\n")
                lines.append(f"**Risk Level**: {ai_analysis.get('risk_level', 'Low')}\n\n")

                # Vulnerability type
                vuln_type = test.get('vulnerability_type', 'Username Enumeration')
                lines.append(f"**Vulnerability Type**: {vuln_type}\n\n")

                # Account Enumeration Warning
                lines.append("⚠️ **Account Enumeration Vulnerability Detected**\n\n")

                # Technical Risk
                lines.append("**Technical Risk**\n\n")
                tech_risk = ai_analysis.get('technical_risk', '')
                if tech_risk:
                    lines.append(f"{tech_risk}\n\n")
                else:
                    lines.append("The login mechanism reveals whether an account exists through different error messages or response patterns. ")
                    lines.append("Attackers can use this information to enumerate valid usernames for:\n\n")
                    lines.append("- **Targeted phishing attacks**: Knowing which accounts exist enables personalized attacks\n")
                    lines.append("- **Credential stuffing**: Valid usernames can be tested with leaked password databases\n")
                    lines.append("- **Social engineering**: Confirmed accounts provide intelligence for social engineering\n")
                    lines.append("- **Reduced brute-force effort**: Only testing against known-valid usernames\n\n")

                # Evidence
                lines.append("**Evidence**\n\n")

                # Extract response data
                invalid_user = test.get('invalid_username_response', {})
                invalid_pass = test.get('invalid_password_response', {})

                if invalid_user and invalid_pass and 'error' not in invalid_user:
                    lines.append("**Response Comparison**:\n\n")
                    lines.append("| Test Scenario | Response Time | Status Code | Content Length | Verdict |\n")
                    lines.append("|---------------|---------------|-------------|----------------|----------|\n")

                    user_time = invalid_user.get('response_time_ms', 'N/A')
                    user_status = invalid_user.get('status_code', 'N/A')
                    user_length = invalid_user.get('content_length', 'N/A')

                    pass_time = invalid_pass.get('response_time_ms', 'N/A')
                    pass_status = invalid_pass.get('status_code', 'N/A')
                    pass_length = invalid_pass.get('content_length', 'N/A')

                    lines.append(f"| Invalid Username | {user_time} ms | {user_status} | {user_length} bytes | Test 1 |\n")
                    lines.append(f"| Invalid Password (admin) | {pass_time} ms | {pass_status} | {pass_length} bytes | Test 2 |\n")

                    lines.append("\n")

                    # Highlight differences
                    if ai_analysis.get('distinguishes_errors'):
                        lines.append("**Observed Differences**:\n\n")
                        security_issues = ai_analysis.get('security_issues', [])
                        for issue in security_issues:
                            lines.append(f"- {issue}\n")
                        lines.append("\n")

                # Remediation
                lines.append("**Remediation**\n\n")

                lines.append("**Priority Fixes** (Implement immediately):\n\n")
                lines.append("1. **Use generic error messages**: Return 'Invalid username or password' for all failed login attempts\n")
                lines.append("2. **Normalize response times**: Ensure consistent response time regardless of username validity\n")
                lines.append("3. **Consistent HTTP status codes**: Always return the same status code (typically 401 or 200 with error message)\n\n")

                lines.append("**Additional Security Controls** (Recommended):\n\n")
                recommendations = ai_analysis.get('recommendations', [])
                if recommendations:
                    for rec in recommendations:
                        if rec not in ['Use generic error messages', 'Implement consistent response times']:
                            lines.append(f"- {rec}\n")
                else:
                    lines.append("- Implement account lockout after 5-10 failed attempts\n")
                    lines.append("- Add CAPTCHA after 3 failed login attempts\n")
                    lines.append("- Implement rate limiting (max 10 attempts per IP per minute)\n")
                    lines.append("- Enable multi-factor authentication (MFA)\n")
                    lines.append("- Monitor and log authentication attempts\n")
                    lines.append("- Send security alerts on multiple failed attempts\n")

                lines.append("\n")

                # References
                lines.append("**References**\n\n")
                lines.append("- **OWASP Top 10 2021**: https://owasp.org/Top10/A04_2021-Insecure_Design/\n")
                lines.append("- **CWE-204**: Observable Response Discrepancy\n")
                lines.append("- **CWE-287**: Improper Authentication\n")
                lines.append("- **OWASP Testing Guide**: Testing for Account Enumeration\n")

                lines.append("\n---\n\n")

    return ''.join(lines)
