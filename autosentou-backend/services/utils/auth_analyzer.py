"""
AuthAnalyzer - Authentication Security Analysis
Analyzes authentication mechanisms for vulnerabilities like username enumeration,
weak password policies, and insecure authentication flows
"""
import requests
import time
import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class AuthAnalyzer:
    """
    Analyzes authentication endpoints for security vulnerabilities:
    - Username enumeration via response differences
    - Timing-based enumeration
    - Weak password policies
    - Missing security controls (rate limiting, CAPTCHA, MFA)
    - Session management issues
    """

    def __init__(self, timeout: int = 10):
        """
        Initialize AuthAnalyzer.

        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        # Test usernames (invalid and common valid ones)
        self.test_usernames = {
            'nonexistent': [
                'nonexistent_user_12345',
                'invalid_username_test_99999',
                'test_user_xyz_doesnotexist'
            ],
            'common': [
                'admin',
                'administrator',
                'root',
                'user',
                'test'
            ]
        }

        logger.info("AuthAnalyzer initialized")

    def analyze_login_endpoint(
        self,
        url: str,
        form_data: Optional[Dict[str, str]] = None,
        method: str = 'POST'
    ) -> Dict[str, Any]:
        """
        Comprehensive analysis of a login endpoint.

        Args:
            url: Login endpoint URL
            form_data: Optional form field names (username_field, password_field)
            method: HTTP method (POST, GET)

        Returns:
            Analysis results
        """
        logger.info(f"Analyzing login endpoint: {url}")

        analysis = {
            'url': url,
            'method': method,
            'timestamp': time.time(),
            'vulnerabilities': [],
            'security_controls': {
                'rate_limiting': False,
                'captcha': False,
                'mfa': False,
                'account_lockout': False
            },
            'enumeration_possible': False,
            'findings': []
        }

        try:
            # Step 1: Discover form fields
            if not form_data:
                form_data = self._discover_form_fields(url)

            analysis['form_fields'] = form_data

            if not form_data or 'username_field' not in form_data:
                analysis['error'] = "Could not identify form fields"
                return analysis

            # Step 2: Test username enumeration
            enumeration_result = self.test_username_enumeration(url, form_data, method)
            analysis.update(enumeration_result)

            # Step 3: Check security controls
            security_controls = self._check_security_controls(url)
            analysis['security_controls'].update(security_controls)

            # Step 4: Test for timing attacks
            timing_result = self._test_timing_based_enumeration(url, form_data, method)
            if timing_result.get('vulnerable'):
                analysis['vulnerabilities'].append({
                    'type': 'Timing-Based Username Enumeration',
                    'severity': 'Low',
                    'cvss': 3.7,
                    'cwe': 'CWE-208',
                    'owasp': 'A04:2021 - Insecure Design',
                    'details': timing_result
                })

            # Step 5: Analyze password policy (if possible)
            password_policy = self._analyze_password_policy(url)
            if password_policy:
                analysis['password_policy'] = password_policy

            # Step 6: Generate overall assessment
            analysis['risk_assessment'] = self._generate_risk_assessment(analysis)

        except Exception as e:
            logger.error(f"Error analyzing login endpoint: {e}", exc_info=True)
            analysis['error'] = str(e)

        return analysis

    def test_username_enumeration(
        self,
        url: str,
        form_data: Dict[str, str],
        method: str = 'POST'
    ) -> Dict[str, Any]:
        """
        Test for username enumeration via response differences.

        Args:
            url: Login endpoint URL
            form_data: Form field names
            method: HTTP method

        Returns:
            Enumeration test results
        """
        logger.info("Testing username enumeration...")

        result = {
            'enumeration_possible': False,
            'enumeration_method': None,
            'test_results': [],
            'evidence': []
        }

        username_field = form_data.get('username_field', 'username')
        password_field = form_data.get('password_field', 'password')
        test_password = 'InvalidPassword123!'

        # Test 1: Non-existent username
        test1_response = self._send_login_request(
            url,
            {
                username_field: self.test_usernames['nonexistent'][0],
                password_field: test_password
            },
            method
        )

        # Test 2: Potentially existing username (admin)
        test2_response = self._send_login_request(
            url,
            {
                username_field: 'admin',
                password_field: test_password
            },
            method
        )

        if not test1_response or not test2_response:
            result['error'] = "Failed to send test requests"
            return result

        # Store test results
        result['test_results'] = [
            {
                'test': 'Invalid Username',
                'username': self.test_usernames['nonexistent'][0],
                'status_code': test1_response.get('status_code'),
                'response_time': test1_response.get('response_time'),
                'content_length': test1_response.get('content_length'),
                'error_message': test1_response.get('error_message')
            },
            {
                'test': 'Potentially Valid Username (admin)',
                'username': 'admin',
                'status_code': test2_response.get('status_code'),
                'response_time': test2_response.get('response_time'),
                'content_length': test2_response.get('content_length'),
                'error_message': test2_response.get('error_message')
            }
        ]

        # Compare responses for differences

        # 1. Check error message differences
        if test1_response['error_message'] != test2_response['error_message']:
            result['enumeration_possible'] = True
            result['enumeration_method'] = 'Error Message Difference'
            result['evidence'].append({
                'type': 'Error Message',
                'invalid_username_message': test1_response['error_message'],
                'valid_username_message': test2_response['error_message'],
                'description': 'Different error messages reveal account existence'
            })

        # 2. Check status code differences
        if test1_response['status_code'] != test2_response['status_code']:
            if not result['enumeration_possible']:
                result['enumeration_possible'] = True
                result['enumeration_method'] = 'Status Code Difference'
            result['evidence'].append({
                'type': 'Status Code',
                'invalid_username_code': test1_response['status_code'],
                'valid_username_code': test2_response['status_code'],
                'description': 'Different status codes reveal account existence'
            })

        # 3. Check content length differences (significant difference)
        length_diff = abs(test1_response['content_length'] - test2_response['content_length'])
        if length_diff > 50:  # More than 50 bytes difference is significant
            if not result['enumeration_possible']:
                result['enumeration_possible'] = True
                result['enumeration_method'] = 'Content Length Difference'
            result['evidence'].append({
                'type': 'Content Length',
                'invalid_username_length': test1_response['content_length'],
                'valid_username_length': test2_response['content_length'],
                'difference': length_diff,
                'description': 'Significant content length difference reveals account existence'
            })

        # 4. Check response time differences (timing attack)
        time_diff = abs(test1_response['response_time'] - test2_response['response_time'])
        if time_diff > 100:  # More than 100ms difference
            if not result['enumeration_possible']:
                result['enumeration_possible'] = True
                result['enumeration_method'] = 'Timing Difference'
            result['evidence'].append({
                'type': 'Response Time',
                'invalid_username_time': test1_response['response_time'],
                'valid_username_time': test2_response['response_time'],
                'difference_ms': time_diff,
                'description': 'Response time difference may reveal account existence'
            })

        if result['enumeration_possible']:
            logger.warning(f"Username enumeration vulnerability detected via {result['enumeration_method']}")
        else:
            logger.info("No username enumeration vulnerability detected")

        return result

    def _send_login_request(
        self,
        url: str,
        data: Dict[str, str],
        method: str = 'POST'
    ) -> Optional[Dict[str, Any]]:
        """
        Send login request and capture response details.

        Args:
            url: Login endpoint URL
            data: Form data
            method: HTTP method

        Returns:
            Response details
        """
        try:
            start_time = time.time()

            if method.upper() == 'POST':
                response = self.session.post(
                    url,
                    data=data,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False
                )
            else:
                response = self.session.get(
                    url,
                    params=data,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False
                )

            response_time = (time.time() - start_time) * 1000  # Convert to ms

            # Extract error message from response
            error_message = self._extract_error_message(response.text)

            return {
                'status_code': response.status_code,
                'response_time': round(response_time, 2),
                'content_length': len(response.content),
                'error_message': error_message,
                'headers': dict(response.headers)
            }

        except Exception as e:
            logger.error(f"Error sending login request: {e}")
            return None

    def _extract_error_message(self, html: str) -> str:
        """
        Extract error message from HTML response.

        Args:
            html: HTML response

        Returns:
            Error message or empty string
        """
        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Common error message selectors
            selectors = [
                '.error', '#error', '.alert', '.message',
                '.alert-danger', '.alert-error', '.error-message',
                '[class*="error"]', '[id*="error"]'
            ]

            for selector in selectors:
                elements = soup.select(selector)
                if elements:
                    text = elements[0].get_text(strip=True)
                    if text:
                        return text

            # Try to find common error phrases
            error_phrases = [
                'invalid', 'incorrect', 'wrong', 'not found',
                'does not exist', 'failed', 'error'
            ]

            for phrase in error_phrases:
                if phrase in html.lower():
                    # Extract surrounding text
                    pattern = re.compile(f'.{{0,50}}{phrase}.{{0,50}}', re.IGNORECASE)
                    match = pattern.search(html)
                    if match:
                        return match.group(0).strip()

            return ""

        except Exception as e:
            logger.debug(f"Error extracting error message: {e}")
            return ""

    def _discover_form_fields(self, url: str) -> Dict[str, str]:
        """
        Discover login form fields from the page.

        Args:
            url: Login page URL

        Returns:
            Dictionary of form field names
        """
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find login form
            forms = soup.find_all('form')
            login_form = None

            # Look for form with login-related action or fields
            for form in forms:
                action = form.get('action', '').lower()
                if any(keyword in action for keyword in ['login', 'signin', 'auth']):
                    login_form = form
                    break

            if not login_form and forms:
                login_form = forms[0]  # Use first form as fallback

            if not login_form:
                return {}

            # Find username field
            username_field = None
            password_field = None

            inputs = login_form.find_all('input')

            for input_tag in inputs:
                input_type = input_tag.get('type', '').lower()
                input_name = input_tag.get('name', '')
                input_id = input_tag.get('id', '').lower()

                # Identify password field
                if input_type == 'password':
                    password_field = input_name

                # Identify username field
                elif input_type in ['text', 'email', '']:
                    if any(keyword in input_name.lower() for keyword in ['user', 'login', 'email', 'account']):
                        username_field = input_name
                    elif any(keyword in input_id for keyword in ['user', 'login', 'email', 'account']):
                        username_field = input_name

            if username_field and password_field:
                logger.info(f"Discovered form fields: {username_field}, {password_field}")
                return {
                    'username_field': username_field,
                    'password_field': password_field
                }

        except Exception as e:
            logger.error(f"Error discovering form fields: {e}")

        return {}

    def _check_security_controls(self, url: str) -> Dict[str, bool]:
        """
        Check for presence of security controls.

        Args:
            url: Login page URL

        Returns:
            Dictionary of security control presence
        """
        controls = {
            'rate_limiting': False,
            'captcha': False,
            'mfa': False,
            'account_lockout': False
        }

        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            html = response.text.lower()

            # Check for CAPTCHA
            if any(indicator in html for indicator in ['captcha', 'recaptcha', 'hcaptcha', 'g-recaptcha']):
                controls['captcha'] = True

            # Check for MFA indicators
            if any(indicator in html for indicator in ['mfa', '2fa', 'two-factor', 'authenticator', 'otp']):
                controls['mfa'] = True

            # Test rate limiting by sending multiple rapid requests
            rate_limit_detected = self._test_rate_limiting(url)
            controls['rate_limiting'] = rate_limit_detected

        except Exception as e:
            logger.debug(f"Error checking security controls: {e}")

        return controls

    def _test_rate_limiting(self, url: str) -> bool:
        """
        Test for rate limiting by sending multiple requests.

        Args:
            url: URL to test

        Returns:
            True if rate limiting detected
        """
        try:
            # Send 5 rapid requests
            for i in range(5):
                response = self.session.get(url, timeout=self.timeout, verify=False)

                # Check for rate limit indicators
                if response.status_code == 429:  # Too Many Requests
                    return True

                if any(indicator in response.text.lower() for indicator in ['rate limit', 'too many', 'slow down']):
                    return True

                time.sleep(0.1)  # Small delay between requests

            return False

        except Exception as e:
            logger.debug(f"Error testing rate limiting: {e}")
            return False

    def _test_timing_based_enumeration(
        self,
        url: str,
        form_data: Dict[str, str],
        method: str
    ) -> Dict[str, Any]:
        """
        Statistical timing analysis for username enumeration.

        Args:
            url: Login endpoint URL
            form_data: Form field names
            method: HTTP method

        Returns:
            Timing analysis results
        """
        result = {
            'vulnerable': False,
            'confidence': 'low',
            'timing_difference_ms': 0
        }

        try:
            username_field = form_data.get('username_field', 'username')
            password_field = form_data.get('password_field', 'password')

            # Collect multiple timing samples
            invalid_times = []
            valid_times = []

            # Test invalid username 5 times
            for _ in range(5):
                response = self._send_login_request(
                    url,
                    {
                        username_field: 'nonexistent_user_timing_test',
                        password_field: 'TestPassword123!'
                    },
                    method
                )
                if response:
                    invalid_times.append(response['response_time'])
                time.sleep(0.5)

            # Test potentially valid username 5 times
            for _ in range(5):
                response = self._send_login_request(
                    url,
                    {
                        username_field: 'admin',
                        password_field: 'TestPassword123!'
                    },
                    method
                )
                if response:
                    valid_times.append(response['response_time'])
                time.sleep(0.5)

            if len(invalid_times) >= 3 and len(valid_times) >= 3:
                avg_invalid = sum(invalid_times) / len(invalid_times)
                avg_valid = sum(valid_times) / len(valid_times)
                diff = abs(avg_invalid - avg_valid)

                result['timing_difference_ms'] = round(diff, 2)
                result['invalid_avg_ms'] = round(avg_invalid, 2)
                result['valid_avg_ms'] = round(avg_valid, 2)

                # Timing difference > 50ms with consistency = vulnerable
                if diff > 50:
                    result['vulnerable'] = True
                    result['confidence'] = 'high' if diff > 100 else 'medium'

        except Exception as e:
            logger.debug(f"Error in timing analysis: {e}")

        return result

    def _analyze_password_policy(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Attempt to analyze password policy requirements.

        Args:
            url: Login or registration page URL

        Returns:
            Password policy information or None
        """
        # This is a placeholder - would need registration page or policy page
        # to fully analyze password requirements
        return None

    def _generate_risk_assessment(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate overall risk assessment.

        Args:
            analysis: Complete analysis results

        Returns:
            Risk assessment
        """
        risk_score = 0
        issues = []

        # Username enumeration
        if analysis.get('enumeration_possible'):
            risk_score += 30
            issues.append('Username enumeration vulnerability detected')

        # Missing security controls
        controls = analysis.get('security_controls', {})
        if not controls.get('rate_limiting'):
            risk_score += 20
            issues.append('No rate limiting detected')

        if not controls.get('captcha'):
            risk_score += 15
            issues.append('No CAPTCHA protection')

        if not controls.get('mfa'):
            risk_score += 10
            issues.append('No MFA (Multi-Factor Authentication) detected')

        # Timing vulnerabilities
        timing_vulns = [v for v in analysis.get('vulnerabilities', [])
                       if 'Timing' in v.get('type', '')]
        if timing_vulns:
            risk_score += 15
            issues.append('Timing-based enumeration possible')

        # Determine overall risk level
        if risk_score >= 60:
            risk_level = 'High'
        elif risk_score >= 30:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'

        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'issues': issues,
            'recommendations': self._generate_recommendations(analysis)
        }

    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """
        Generate security recommendations.

        Args:
            analysis: Analysis results

        Returns:
            List of recommendations
        """
        recommendations = []

        if analysis.get('enumeration_possible'):
            recommendations.append(
                "Implement generic error messages: Always return 'Invalid username or password' "
                "for all authentication failures"
            )
            recommendations.append(
                "Normalize response times: Ensure consistent response times for both valid "
                "and invalid usernames (use constant-time comparison)"
            )

        controls = analysis.get('security_controls', {})
        if not controls.get('rate_limiting'):
            recommendations.append(
                "Implement rate limiting: Limit failed login attempts to 5-10 per IP/account per time window"
            )

        if not controls.get('captcha'):
            recommendations.append(
                "Add CAPTCHA: Implement CAPTCHA after 3-5 failed login attempts to prevent automation"
            )

        if not controls.get('mfa'):
            recommendations.append(
                "Enable Multi-Factor Authentication (MFA): Add optional or mandatory MFA for enhanced security"
            )

        if not controls.get('account_lockout'):
            recommendations.append(
                "Implement account lockout: Lock accounts after 5-10 failed attempts with time-based unlock"
            )

        recommendations.append(
            "Implement comprehensive logging: Log all authentication attempts with timestamps, IPs, and user agents"
        )

        return recommendations

    def batch_analyze_login_pages(self, login_urls: List[str]) -> Dict[str, Any]:
        """
        Analyze multiple login pages.

        Args:
            login_urls: List of login page URLs

        Returns:
            Batch analysis results
        """
        logger.info(f"Batch analyzing {len(login_urls)} login pages")

        results = {
            'total_pages': len(login_urls),
            'analyzed': 0,
            'vulnerable': 0,
            'secure': 0,
            'errors': 0,
            'results': []
        }

        for url in login_urls:
            try:
                analysis = self.analyze_login_endpoint(url)
                results['results'].append(analysis)
                results['analyzed'] += 1

                if analysis.get('enumeration_possible'):
                    results['vulnerable'] += 1
                else:
                    results['secure'] += 1

            except Exception as e:
                logger.error(f"Error analyzing {url}: {e}")
                results['errors'] += 1
                results['results'].append({
                    'url': url,
                    'error': str(e)
                })

            # Small delay to avoid overwhelming the target
            time.sleep(1)

        logger.info(f"Batch analysis complete: {results['vulnerable']} vulnerable, "
                   f"{results['secure']} secure, {results['errors']} errors")

        return results
