"""
Result Validator
Validates PoC execution results to determine true success
"""
import re
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ResultValidator:
    """
    Validates PoC execution results using multiple methods:
    - Success indicators matching
    - Error pattern detection
    - Output analysis
    - Confidence scoring
    """

    # Common error patterns that indicate failure
    ERROR_PATTERNS = [
        r'error:',
        r'failed',
        r'connection refused',
        r'timeout',
        r'not found',
        r'permission denied',
        r'access denied',
        r'invalid',
        r'exception',
        r'traceback',
        r'cannot connect',
        r'unreachable'
    ]

    # Positive indicators of success
    SUCCESS_PATTERNS = [
        r'success',
        r'exploit.*successful',
        r'shell',
        r'owned',
        r'pwned',
        r'vulnerable',
        r'exploit.*worked'
    ]

    def validate_result(
        self,
        execution_result: Dict[str, Any],
        exploit: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate PoC execution result.

        Args:
            execution_result: Result from PoCExecutor
            exploit: Original exploit information

        Returns:
            Validation result with confidence score
        """
        validation = {
            'is_successful': False,
            'confidence_score': 0.0,
            'validation_method': '',
            'indicators_found': [],
            'errors_detected': [],
            'analysis': ''
        }

        try:
            output = execution_result.get('output', '')
            error_output = execution_result.get('error', '')
            returncode = execution_result.get('returncode', -1)
            combined_output = output + '\n' + error_output

            # Method 1: Check explicit success indicators
            success_indicators = exploit.get('success_indicators', [])
            if success_indicators:
                found_indicators = self._check_indicators(combined_output, success_indicators)
                if found_indicators:
                    validation['indicators_found'] = found_indicators
                    validation['confidence_score'] += 60.0
                    validation['validation_method'] = 'success_indicators'

            # Method 2: Check for error patterns
            errors_detected = self._detect_errors(combined_output)
            if errors_detected:
                validation['errors_detected'] = errors_detected
                validation['confidence_score'] -= 30.0

            # Method 3: Analyze return code
            if returncode == 0:
                validation['confidence_score'] += 20.0
            elif returncode != 0 and validation['confidence_score'] > 0:
                validation['confidence_score'] -= 10.0

            # Method 4: Check for general success patterns
            if not success_indicators:
                general_success = self._check_general_success(combined_output)
                if general_success:
                    validation['confidence_score'] += 40.0
                    validation['validation_method'] = 'general_patterns'

            # Method 5: Output length analysis (meaningful output vs empty)
            if len(output.strip()) > 50:  # At least 50 chars of output
                validation['confidence_score'] += 10.0

            # Check timeout
            if execution_result.get('timeout_exceeded'):
                validation['confidence_score'] -= 20.0
                validation['errors_detected'].append('timeout_exceeded')

            # Final determination
            validation['confidence_score'] = max(0, min(100, validation['confidence_score']))

            if validation['confidence_score'] >= 60:
                validation['is_successful'] = True
                validation['analysis'] = f"High confidence success ({validation['confidence_score']:.1f}%)"
            elif validation['confidence_score'] >= 40:
                validation['is_successful'] = True
                validation['analysis'] = f"Moderate confidence success ({validation['confidence_score']:.1f}%)"
            else:
                validation['is_successful'] = False
                validation['analysis'] = f"Likely failed ({validation['confidence_score']:.1f}% confidence)"

            logger.info(f"Validation result: {validation['analysis']}")

        except Exception as e:
            logger.error(f"Error validating result: {e}", exc_info=True)
            validation['analysis'] = f"Validation error: {str(e)}"

        return validation

    def _check_indicators(self, output: str, indicators: List[str]) -> List[str]:
        """
        Check for success indicators in output.

        Args:
            output: Command output
            indicators: List of success indicators

        Returns:
            List of found indicators
        """
        found = []
        output_lower = output.lower()

        for indicator in indicators:
            if indicator.lower() in output_lower:
                found.append(indicator)
                logger.info(f"Found success indicator: {indicator}")

        return found

    def _detect_errors(self, output: str) -> List[str]:
        """
        Detect error patterns in output.

        Args:
            output: Command output

        Returns:
            List of detected error patterns
        """
        detected = []
        output_lower = output.lower()

        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, output_lower):
                detected.append(pattern)
                logger.info(f"Detected error pattern: {pattern}")

        return detected

    def _check_general_success(self, output: str) -> bool:
        """
        Check for general success patterns when specific indicators not available.

        Args:
            output: Command output

        Returns:
            True if general success patterns found
        """
        output_lower = output.lower()

        for pattern in self.SUCCESS_PATTERNS:
            if re.search(pattern, output_lower):
                logger.info(f"Found general success pattern: {pattern}")
                return True

        return False

    def analyze_exploit_type_success(self, execution_result: Dict[str, Any], exploit_type: str) -> bool:
        """
        Analyze success based on exploit type.

        Args:
            execution_result: Execution result
            exploit_type: Type of exploit (e.g., "Path Traversal", "RCE", "SQLi")

        Returns:
            True if exploit-specific success indicators found
        """
        output = execution_result.get('output', '') + execution_result.get('error', '')
        output_lower = output.lower()

        type_indicators = {
            'path traversal': ['root:', '/etc/passwd', '[boot loader]', 'system32'],
            'rce': ['uid=', 'gid=', 'shell', 'cmd.exe', '$'],
            'sqli': ['mysql', 'database', 'union', 'select', 'table'],
            'xss': ['<script>', 'alert(', 'javascript:'],
            'user enumeration': ['valid', 'exists', 'found', 'user'],
            'file inclusion': ['<?php', 'include', 'require'],
            'buffer overflow': ['segmentation fault', 'core dumped', 'shell'],
            'information disclosure': ['version', 'server', 'apache', 'nginx', 'iis']
        }

        exploit_type_lower = exploit_type.lower()

        for key, indicators in type_indicators.items():
            if key in exploit_type_lower:
                for indicator in indicators:
                    if indicator in output_lower:
                        logger.info(f"Found {exploit_type} indicator: {indicator}")
                        return True

        return False

    def compare_with_expected_output(self, actual_output: str, expected_patterns: List[str]) -> float:
        """
        Compare actual output with expected patterns.

        Args:
            actual_output: Actual command output
            expected_patterns: Expected output patterns

        Returns:
            Match percentage (0-100)
        """
        if not expected_patterns:
            return 50.0  # Neutral if no expected patterns

        matches = 0
        for pattern in expected_patterns:
            if re.search(pattern, actual_output, re.IGNORECASE):
                matches += 1

        match_percentage = (matches / len(expected_patterns)) * 100
        return match_percentage
