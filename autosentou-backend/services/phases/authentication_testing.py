#  services/phases/authentication_testing.py
"""
Authentication Testing Phase

Tests login pages for security vulnerabilities:
- Username enumeration (OWASP A04:2021 - Insecure Design)
- Different error messages for invalid username vs invalid password
- Response timing analysis
- Missing security controls (rate limiting, CAPTCHA)

Does NOT perform brute-force attacks.
"""
import os
import json
import re
import requests
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from models import Phase, Job
from services.ai.ai_service import init_ai_service
from services.utils.output_manager import get_output_manager
from services.utils.auth_analyzer import AuthAnalyzer
from services.utils.sqlmap_wrapper import SQLMapWrapper

logger = logging.getLogger(__name__)

ai_service = init_ai_service()


def test_login_response_security(url: str, username_field: str = 'username', password_field: str = 'password') -> Dict[str, Any]:
    """
    Test login page for username enumeration vulnerability.

    Tests two scenarios:
    1. Non-existent account + any password
    2. Existing account (assumes 'admin') + wrong password

    Security Assessment:
    - SECURE: Both return "Account or password incorrect"
    - VULNERABLE: Different messages reveal account existence

    Args:
        url: Login page URL
        username_field: Username field name (default: 'username')
        password_field: Password field name (default: 'password')

    Returns:
        Dictionary containing test results and AI analysis
    """
    logger.info(f"Testing login response security for {url}...")

    # Test 1: Invalid username
    invalid_username_response = None
    invalid_username_time = None

    try:
        import time
        start_time = time.time()

        response = requests.post(
            url,
            data={
                username_field: 'nonexistent_user_12345',
                password_field: 'randompassword123'
            },
            timeout=10,
            allow_redirects=False
        )

        end_time = time.time()
        invalid_username_time = int((end_time - start_time) * 1000)  # milliseconds

        invalid_username_response = {
            'status_code': response.status_code,
            'text': response.text[:1000],  # Limit to first 1000 chars
            'headers': dict(response.headers),
            'response_time_ms': invalid_username_time,
            'content_length': len(response.content)
        }
    except Exception as e:
        logger.error(f"Error testing invalid username: {e}")
        invalid_username_response = {'error': str(e)}

    # Test 2: Valid username but invalid password (assumes 'admin' exists)
    invalid_password_response = None
    invalid_password_time = None

    try:
        import time
        start_time = time.time()

        response = requests.post(
            url,
            data={
                username_field: 'admin',
                password_field: 'wrongpassword123'
            },
            timeout=10,
            allow_redirects=False
        )

        end_time = time.time()
        invalid_password_time = int((end_time - start_time) * 1000)

        invalid_password_response = {
            'status_code': response.status_code,
            'text': response.text[:1000],
            'headers': dict(response.headers),
            'response_time_ms': invalid_password_time,
            'content_length': len(response.content)
        }
    except Exception as e:
        logger.error(f"Error testing invalid password: {e}")
        invalid_password_response = {'error': str(e)}

    # Analyze responses with AI
    if invalid_username_response and invalid_password_response and 'error' not in invalid_username_response:
        comparison = f"""
Response for invalid username (nonexistent_user_12345):
Status: {invalid_username_response.get('status_code')}
Response Time: {invalid_username_response.get('response_time_ms')}ms
Content Length: {invalid_username_response.get('content_length')} bytes
Text: {invalid_username_response.get('text', '')[:500]}

Response for invalid password (username: admin):
Status: {invalid_password_response.get('status_code')}
Response Time: {invalid_password_response.get('response_time_ms')}ms
Content Length: {invalid_password_response.get('content_length')} bytes
Text: {invalid_password_response.get('text', '')[:500]}
"""

        ai_analysis = ai_service.analyze_login_response(
            comparison,
            invalid_username_response.get('status_code', 0)
        )

        # Add classification
        if ai_analysis.get('account_enumeration_possible'):
            ai_analysis['classification'] = {
                'owasp': 'A04:2021 - Insecure Design',
                'severity': 'Low',
                'cvss': '3.7',  # Low severity username enumeration
                'cwe': 'CWE-204: Observable Response Discrepancy'
            }

    else:
        ai_analysis = {
            'reveals_username_exists': False,
            'distinguishes_errors': False,
            'account_enumeration_possible': False,
            'security_issues': ['Could not test login responses - connection error'],
            'recommendations': ['Ensure login page is accessible', 'Verify the login endpoint URL'],
            'risk_level': 'Unknown'
        }

    return {
        'url': url,
        'invalid_username_response': invalid_username_response,
        'invalid_password_response': invalid_password_response,
        'ai_analysis': ai_analysis,
        'security_issues_found': ai_analysis.get('account_enumeration_possible', False),
        'vulnerability_type': 'Username Enumeration' if ai_analysis.get('account_enumeration_possible') else None
    }


def run_authentication_testing_phase(db_session, job: Job, web_enum_data: Dict[str, Any]) -> Optional[Phase]:
    """
    Run authentication testing phase on identified login pages.

    Tests for:
    - Username enumeration vulnerabilities
    - Response discrepancies between invalid username and invalid password
    - Missing security controls

    Does NOT perform brute-force attacks.

    Args:
        db_session: Database session
        job: Job object
        web_enum_data: Web enumeration phase data

    Returns:
        Phase object with test results
    """
    phase = Phase(
        job_id=job.id,
        phase_name="Authentication Testing",
        data={},
        log_path=None,
        status="ongoing",
    )
    db_session.add(phase)
    db_session.commit()
    db_session.refresh(phase)

    try:
        logger.info("="*80)
        logger.info(f"[Job {job.id}] STARTING AUTHENTICATION TESTING PHASE")
        logger.info("="*80)

        # Initialize output manager
        output_mgr = get_output_manager(job.id)

        # Get login pages from web enumeration
        ai_rag_analysis = web_enum_data.get('ai_rag_analysis', {})
        login_pages = ai_rag_analysis.get('login_pages', [])

        # Also check fingerprints for login indicators
        fingerprints = web_enum_data.get('server_fingerprints', [])
        for fingerprint in fingerprints:
            if fingerprint.get('login_indicators') and fingerprint.get('url'):
                # Add base URL as potential login page if it has login indicators
                url = fingerprint['url']
                if not any(lp.get('url') == url for lp in login_pages):
                    login_pages.append({
                        'url': url,
                        'reason': 'Login indicators detected in fingerprint'
                    })

        if not login_pages:
            phase.data = {
                'message': 'No login pages identified for authentication testing',
                'login_pages_tested': 0,
                'testing_type': 'Username Enumeration Detection'
            }
            phase.status = "success"
            phase.updated_at = datetime.now()
            db_session.add(phase)
            db_session.commit()
            db_session.refresh(phase)

            logger.warning(f"[Job {job.id}] No login pages found to test.")
            return phase

        # Create output directory
        output_dir = f"reports/{job.id}/authentication_testing"
        os.makedirs(output_dir, exist_ok=True)

        # Initialize analyzers
        auth_analyzer = AuthAnalyzer()
        sqlmap_wrapper = SQLMapWrapper(level=1, risk=1, output_dir=output_dir)

        login_response_tests = []
        vulnerable_login_count = 0
        vulnerabilities_found = []
        sqlmap_results = []

        # Test each login page
        logger.info(f"[Job {job.id}] Testing {len(login_pages[:5])} login page(s)...")

        for idx, login_page in enumerate(login_pages[:5], 1):  # Limit to 5 login pages
            url = login_page.get('url', '')

            if not url:
                continue

            logger.info(f"[Job {job.id}] [{idx}/{min(len(login_pages), 5)}] Testing: {url}")

            # Use AuthAnalyzer for comprehensive testing
            analysis_result = auth_analyzer.analyze_login_endpoint(url)
            login_response_tests.append(analysis_result)

            # Check for username enumeration
            if analysis_result.get('enumeration_possible'):
                vulnerable_login_count += 1
                vulnerabilities_found.append({
                    'url': url,
                    'type': 'Username Enumeration',
                    'owasp': 'A04:2021 - Insecure Design',
                    'severity': 'Low',
                    'method': analysis_result.get('enumeration_method'),
                    'evidence': analysis_result.get('evidence', []),
                    'description': 'Login page reveals whether accounts exist through different error messages or response patterns'
                })
                logger.warning(f"[Job {job.id}]   ⚠️ Username enumeration: {analysis_result.get('enumeration_method')}")
            else:
                logger.info(f"[Job {job.id}]   ✓ No username enumeration detected")

            # Check for SQLi indicators
            if analysis_result.get('sqli_indicators', {}).get('indicators_found'):
                sqli_data = analysis_result['sqli_indicators']
                indicator_types = ', '.join(sqli_data['indicator_types'])
                logger.warning(f"[Job {job.id}]   ⚠️ SQL injection indicators: {indicator_types}")

                # Automatically run SQLMap
                logger.info(f"[Job {job.id}]   🔍 Auto-launching SQLMap (Level 1, safe)...")

                sqlmap_params = sqli_data.get('sqlmap_params', {})
                sqlmap_result = sqlmap_wrapper.test_endpoint(
                    url=sqlmap_params.get('url', url),
                    method=sqlmap_params.get('method', 'POST'),
                    data=sqlmap_params.get('data'),
                    test_parameter=sqlmap_params.get('testParameter')
                )

                sqlmap_results.append(sqlmap_result)

                if sqlmap_result.get('vulnerable'):
                    vulnerabilities_found.append({
                        'url': url,
                        'type': 'SQL Injection',
                        'owasp': 'A03:2021 - Injection',
                        'severity': 'Critical',
                        'cvss': 9.8,
                        'techniques': [v.get('technique', 'Unknown') for v in sqlmap_result.get('vulnerabilities', [])],
                        'description': 'SQL injection vulnerability confirmed by SQLMap',
                        'sqlmap_output': sqlmap_result.get('output_file')
                    })
                    logger.error(f"[Job {job.id}]   ❌ CRITICAL: SQL injection CONFIRMED by SQLMap!")
                else:
                    logger.info(f"[Job {job.id}]   ✓ SQLMap: No exploitable SQL injection found")

            # SAVE AUTH TEST OUTPUT
            auth_paths = output_mgr.save_auth_test_output(
                url=url,
                test_data=analysis_result
            )
            analysis_result['saved_files'] = auth_paths

        # Combine results
        sql_injection_count = len([v for v in vulnerabilities_found if v['type'] == 'SQL Injection'])

        combined_data = {
            'testing_type': 'Enhanced Authentication Security Analysis',
            'login_pages_tested': len(login_response_tests),
            'login_response_tests': login_response_tests,
            'vulnerable_login_pages': vulnerable_login_count,
            'vulnerabilities_found': vulnerabilities_found,
            'sqlmap_results': sqlmap_results,
            'security_summary': {
                'username_enumeration': vulnerable_login_count,
                'sql_injection_confirmed': sql_injection_count,
                'total_critical': sql_injection_count,
                'total_low': vulnerable_login_count,
                'secure_implementations': len(login_response_tests) - vulnerable_login_count - sql_injection_count
            },
            'testing_timestamp': datetime.now().isoformat(),
            'note': 'Tests for username enumeration and SQL injection. SQLMap runs automatically when indicators are detected. Brute-force attacks are NOT performed.'
        }

        # SAVE COMPLETE PHASE DATA
        phase_data_path = output_mgr.save_phase_data('authentication_testing', combined_data)
        combined_data['phase_data_file'] = phase_data_path

        phase.data = combined_data
        phase.status = "success"
        phase.updated_at = datetime.now()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)

        logger.info("="*80)
        logger.info(f"[Job {job.id}] AUTHENTICATION TESTING PHASE COMPLETED")
        logger.info(f"[Job {job.id}] Tested: {len(login_response_tests)} login page(s)")
        logger.info(f"[Job {job.id}] Username enumeration: {vulnerable_login_count} vulnerable")
        logger.info(f"[Job {job.id}] SQL injection: {sql_injection_count} CONFIRMED by SQLMap")
        logger.info(f"[Job {job.id}] Secure: {len(login_response_tests) - vulnerable_login_count - sql_injection_count} page(s)")
        logger.info("="*80)

        return phase

    except Exception as e:
        import traceback
        phase.data = {
            "error": str(e),
            "traceback": traceback.format_exc()
        }
        phase.status = "failed"
        phase.updated_at = datetime.now()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)
        logger.error(f"[Job {job.id}] Authentication testing failed: {str(e)}", exc_info=True)
        return phase


# Backward compatibility alias
run_brute_force_testing_phase = run_authentication_testing_phase
