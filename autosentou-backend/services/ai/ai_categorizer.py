"""
AI-Powered Vulnerability Categorization Service
Uses LLMs (Gemini, OpenAI, DeepSeek, Ollama) to intelligently categorize vulnerabilities
"""
import logging
import json
from typing import Dict, Any, Optional, List
from services.ai.ai_service import get_ai_service
from services.ai.prompts import get_single_categorization_prompt, get_batch_categorization_prompt

logger = logging.getLogger(__name__)


class AICategorizer:
    """
    Uses AI models to intelligently categorize vulnerabilities.
    Provides severity, OWASP category, CWE, and remediation suggestions.
    """

    def __init__(self):
        self.ai_service = get_ai_service()
        logger.info("✓ AI Categorizer initialized")

    def categorize(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Use AI to categorize a vulnerability finding.

        Args:
            finding: Dictionary containing vulnerability details
                     {title, description, finding_type, url, service, etc.}

        Returns:
            Dictionary with categorization results:
            {
                'severity': 'Critical|High|Medium|Low',
                'owasp_category': 'A01:2021 - Category Name',
                'cwe_id': 'CWE-XXX',
                'category': 'Descriptive category',
                'remediation': 'Detailed remediation steps',
                'cvss_estimate': float,
                'reasoning': 'Why this categorization was chosen'
            }
        """
        try:
            prompt = self._build_categorization_prompt(finding)
            response = self.ai_service.generate(prompt)

            if not response:
                return None

            # Parse AI response
            categorization = self._parse_ai_response(response)

            if categorization:
                logger.info(f"✓ AI categorized: {finding.get('title')} → "
                          f"{categorization['severity']} / {categorization['owasp_category']}")

            return categorization

        except Exception as e:
            logger.error(f"✗ AI categorization error: {e}", exc_info=True)
            return None

    def _build_categorization_prompt(self, finding: Dict[str, Any]) -> str:
        """Build a detailed prompt for AI categorization using centralized prompts."""
        return get_single_categorization_prompt(finding)

    def categorize_batch(self, findings: List[Dict[str, Any]]) -> List[Optional[Dict[str, Any]]]:
        """
        Batch categorize multiple findings in a single AI call.

        Args:
            findings: List of finding dictionaries

        Returns:
            List of categorization results (same order as input)
        """
        try:
            prompt = get_batch_categorization_prompt(findings)
            response = self.ai_service.generate(prompt)

            if not response:
                return [None] * len(findings)

            # Parse batch response
            results = self._parse_batch_ai_response(response, len(findings))

            if results and len(results) == len(findings):
                logger.info(f"✓ AI batch categorized {len(findings)} findings")
                return results
            else:
                logger.warning(f"⚠ Batch response mismatch: expected {len(findings)}, got {len(results) if results else 0}")
                return [None] * len(findings)

        except Exception as e:
            logger.error(f"✗ AI batch categorization error: {e}", exc_info=True)
            return [None] * len(findings)

    def _parse_ai_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse JSON response from AI model."""
        try:
            # Clean up response (remove markdown code blocks if present)
            response = response.strip()
            if response.startswith("```json"):
                response = response[7:]
            if response.startswith("```"):
                response = response[3:]
            if response.endswith("```"):
                response = response[:-3]
            response = response.strip()

            # Parse JSON
            result = json.loads(response)

            # Validate required fields
            required_fields = ['severity', 'owasp_category', 'category', 'remediation']
            for field in required_fields:
                if field not in result:
                    logger.warning(f"Missing required field in AI response: {field}")
                    return None

            # Ensure severity is capitalized
            result['severity'] = result['severity'].capitalize()

            return result

        except json.JSONDecodeError as e:
            logger.error(f"✗ Failed to parse AI JSON response: {e}")
            logger.debug(f"Response was: {response}")
            return None
        except Exception as e:
            logger.error(f"✗ Error parsing AI response: {e}")
            return None

    def _parse_batch_ai_response(self, response: str, expected_count: int) -> List[Optional[Dict[str, Any]]]:
        """Parse batch JSON response from AI model."""
        try:
            # Clean up response
            response = response.strip()
            if response.startswith("```json"):
                response = response[7:]
            if response.startswith("```"):
                response = response[3:]
            if response.endswith("```"):
                response = response[:-3]
            response = response.strip()

            # Parse JSON array
            results = json.loads(response)

            if not isinstance(results, list):
                logger.error("Batch response is not a JSON array")
                return [None] * expected_count

            # Validate and clean each result
            cleaned_results = []
            for result in results:
                # Validate required fields
                required_fields = ['severity', 'owasp_category', 'category', 'remediation']
                valid = all(field in result for field in required_fields)

                if valid:
                    # Ensure severity is capitalized
                    result['severity'] = result['severity'].capitalize()
                    cleaned_results.append(result)
                else:
                    logger.warning(f"Missing required fields in batch result: {result}")
                    cleaned_results.append(None)

            return cleaned_results

        except json.JSONDecodeError as e:
            logger.error(f"✗ Failed to parse batch AI JSON response: {e}")
            logger.debug(f"Response was: {response[:500]}")
            return [None] * expected_count
        except Exception as e:
            logger.error(f"✗ Error parsing batch AI response: {e}")
            return [None] * expected_count


# Global instance
_ai_categorizer_instance = None


def get_ai_categorizer() -> AICategorizer:
    """Get or create the global AI categorizer instance."""
    global _ai_categorizer_instance
    if _ai_categorizer_instance is None:
        _ai_categorizer_instance = AICategorizer()
    return _ai_categorizer_instance


def ai_categorize_finding(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Convenience function to categorize a finding using AI.

    Args:
        finding: Finding dictionary

    Returns:
        Categorization result or None if failed
    """
    categorizer = get_ai_categorizer()
    return categorizer.categorize(finding)


def ai_categorize_findings_batch(findings: List[Dict[str, Any]]) -> List[Optional[Dict[str, Any]]]:
    """
    Convenience function to batch categorize multiple findings using AI.

    Args:
        findings: List of finding dictionaries

    Returns:
        List of categorization results (same order as input)
    """
    categorizer = get_ai_categorizer()
    return categorizer.categorize_batch(findings)
