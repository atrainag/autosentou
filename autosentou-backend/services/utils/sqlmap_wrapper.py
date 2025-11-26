"""
services/utils/sqlmap_wrapper.py
Minimal wrapper for SQLMap automated SQL injection testing
"""
import os
import json
import logging
import subprocess
import tempfile
import random
from typing import Dict, Any, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)


class SQLMapWrapper:
    """
    Wrapper for SQLMap automated SQL injection testing.

    Features:
    - Automatic execution with random user-agent
    - Level 1 (safe) by default
    - Captures results in JSON format
    - Handles POST/GET requests with form data
    """

    def __init__(
        self,
        level: int = 1,
        risk: int = 1,
        timeout: int = 300,
        output_dir: str = "./reports"
    ):
        """
        Initialize SQLMap wrapper.

        Args:
            level: Detection level (1-5, default 1 = safe)
            risk: Risk level (1-3, default 1 = safe)
            timeout: Timeout in seconds
            output_dir: Output directory for results
        """
        self.level = level
        self.risk = risk
        self.timeout = timeout
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Random user agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15'
        ]

        logger.info(f"SQLMapWrapper initialized (level={level}, risk={risk})")

    def test_endpoint(
        self,
        url: str,
        method: str = 'POST',
        data: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        test_parameter: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Test endpoint for SQL injection vulnerabilities.

        Args:
            url: Target URL
            method: HTTP method (POST/GET)
            data: Form data dict
            cookies: Session cookies
            test_parameter: Specific parameter to test (e.g., 'username')

        Returns:
            Results dict with vulnerability findings
        """
        logger.info(f"Testing endpoint with SQLMap: {url}")

        result = {
            'url': url,
            'method': method,
            'vulnerable': False,
            'vulnerabilities': [],
            'output_file': None,
            'command_executed': None,
            'error': None
        }

        try:
            # Build SQLMap command
            cmd = self._build_command(url, method, data, cookies, test_parameter)
            result['command_executed'] = ' '.join(cmd)

            logger.info(f"Executing: {result['command_executed']}")

            # Execute SQLMap
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=os.getcwd()
            )

            stdout, stderr = process.communicate(timeout=self.timeout)

            # Parse output
            vulnerabilities = self._parse_output(stdout)

            if vulnerabilities:
                result['vulnerable'] = True
                result['vulnerabilities'] = vulnerabilities
                logger.warning(f"SQL injection vulnerabilities found: {len(vulnerabilities)}")
            else:
                logger.info("No SQL injection vulnerabilities detected")

            # Save output
            output_file = self._save_output(url, stdout, stderr)
            result['output_file'] = str(output_file)

            return result

        except subprocess.TimeoutExpired:
            logger.error(f"SQLMap timeout after {self.timeout}s")
            result['error'] = f"Timeout after {self.timeout}s"
            return result

        except Exception as e:
            logger.error(f"SQLMap execution failed: {e}")
            result['error'] = str(e)
            return result

    def _build_command(
        self,
        url: str,
        method: str,
        data: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]],
        test_parameter: Optional[str]
    ) -> List[str]:
        """Build SQLMap command with parameters."""
        cmd = ['sqlmap']

        # Target URL
        cmd.extend(['-u', url])

        # Method and data
        if method.upper() == 'POST' and data:
            # Format data for SQLMap
            data_str = '&'.join([f"{k}={v}" for k, v in data.items()])
            cmd.extend(['--data', data_str])

        # Cookies
        if cookies:
            cookie_str = '; '.join([f"{k}={v}" for k, v in cookies.items()])
            cmd.extend(['--cookie', cookie_str])

        # Test specific parameter
        if test_parameter:
            cmd.extend(['-p', test_parameter])

        # Random user agent
        random_ua = random.choice(self.user_agents)
        cmd.extend(['--user-agent', random_ua])

        # Safety settings
        cmd.extend([
            '--level', str(self.level),
            '--risk', str(self.risk),
            '--batch',  # Non-interactive
            '--random-agent',  # Randomize agent
            '--threads', '4',  # Speed up
            '--technique', 'BEUSTQ',  # All techniques
            '--tamper', 'space2comment',  # Basic evasion
        ])

        # Output options
        cmd.extend([
            '--no-logging',  # Disable console logging
            '--flush-session',  # Fresh session
        ])

        return cmd

    def _parse_output(self, stdout: str) -> List[Dict[str, Any]]:
        """
        Parse SQLMap output for vulnerabilities.

        Args:
            stdout: SQLMap stdout

        Returns:
            List of vulnerability dicts
        """
        vulnerabilities = []

        # Look for "Parameter: X is vulnerable" lines
        lines = stdout.split('\n')

        for line in lines:
            if 'is vulnerable' in line.lower() or 'injectable' in line.lower():
                # Extract parameter name and type
                vuln = {
                    'description': line.strip(),
                    'type': 'SQL Injection',
                    'severity': 'Critical'
                }

                # Try to extract technique
                if 'boolean-based' in line.lower():
                    vuln['technique'] = 'Boolean-based blind'
                elif 'time-based' in line.lower():
                    vuln['technique'] = 'Time-based blind'
                elif 'error-based' in line.lower():
                    vuln['technique'] = 'Error-based'
                elif 'union' in line.lower():
                    vuln['technique'] = 'UNION query'
                elif 'stacked' in line.lower():
                    vuln['technique'] = 'Stacked queries'

                vulnerabilities.append(vuln)

        return vulnerabilities

    def _save_output(self, url: str, stdout: str, stderr: str) -> Path:
        """Save SQLMap output to file."""
        import hashlib
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]

        output_file = self.output_dir / f"sqlmap_{url_hash}.txt"

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"SQLMap Results for: {url}\n")
            f.write("=" * 80 + "\n\n")
            f.write("STDOUT:\n")
            f.write(stdout)
            f.write("\n\nSTDERR:\n")
            f.write(stderr)

        logger.info(f"SQLMap output saved: {output_file}")
        return output_file


def run_sqlmap_test(
    url: str,
    method: str = 'POST',
    data: Optional[Dict[str, str]] = None,
    test_parameter: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience function to run SQLMap test.

    Args:
        url: Target URL
        method: HTTP method
        data: Form data
        test_parameter: Parameter to test

    Returns:
        Results dict
    """
    wrapper = SQLMapWrapper(level=1, risk=1)
    return wrapper.test_endpoint(url, method, data, test_parameter=test_parameter)
