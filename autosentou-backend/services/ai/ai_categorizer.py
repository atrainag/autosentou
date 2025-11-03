"""
AI-Powered Vulnerability Categorization Service
Uses LLMs (Gemini, OpenAI, DeepSeek, Ollama) to intelligently categorize vulnerabilities
"""
import logging
import json
from typing import Dict, Any, Optional
from services.ai.ai_service import get_ai_service

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
        """Build a detailed prompt for AI categorization."""
        return f"""You are a cybersecurity expert specializing in vulnerability assessment and OWASP Top 10.

Analyze the following vulnerability finding and provide a detailed categorization.

**Finding Information:**
- Title: {finding.get('title', 'N/A')}
- Description: {finding.get('description', 'N/A')}
- Type: {finding.get('finding_type', 'N/A')}
- URL: {finding.get('url', 'N/A')}
- Service: {finding.get('service', 'N/A')}
- Port: {finding.get('port', 'N/A')}
- CVE ID: {finding.get('cve_id', 'N/A')}
- Evidence: {json.dumps(finding.get('evidence', {}), indent=2)}

**Task:**
Categorize this vulnerability using the OWASP Top 10 2021 framework.

**OWASP Top 10 2021 Categories:**
A01:2021 - Broken Access Control
A02:2021 - Cryptographic Failures
A03:2021 - Injection
A04:2021 - Insecure Design
A05:2021 - Security Misconfiguration
A06:2021 - Vulnerable and Outdated Components
A07:2021 - Identification and Authentication Failures
A08:2021 - Software and Data Integrity Failures
A09:2021 - Security Logging and Monitoring Failures
A10:2021 - Server-Side Request Forgery (SSRF)

**Respond ONLY with valid JSON in this exact format:**
{{
  "severity": "Critical|High|Medium|Low",
  "owasp_category": "A0X:2021 - Full Category Name",
  "cwe_id": "CWE-XXX",
  "category": "Brief descriptive category name",
  "remediation": "Detailed remediation steps (2-3 sentences)",
  "cvss_estimate": 0.0,
  "reasoning": "Brief explanation of why this categorization (1-2 sentences)"
}}

Provide your response as valid JSON only, no other text."""

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
