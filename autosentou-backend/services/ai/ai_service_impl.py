"""
AI Service implementation with dependency injection.

This is the refactored version that implements IAIService interface.
"""

from typing import Dict, Any, Optional
import google.generativeai as genai
from openai import OpenAI

from core.interfaces import IAIService
from core.models import ServiceConfig


class AIServiceImpl(IAIService):
    """
    AI Service with dependency injection.

    Supports multiple AI providers (Gemini, OpenAI) via configuration.
    """

    def __init__(self, config: ServiceConfig):
        self.config = config
        self._client = None
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize AI client based on provider"""
        if self.config.ai_provider == "gemini":
            if not self.config.gemini_api_key:
                raise ValueError("Gemini API key not configured")
            genai.configure(api_key=self.config.gemini_api_key)
            self._client = genai.GenerativeModel(self.config.ai_model or 'gemini-1.5-flash')
        elif self.config.ai_provider == "openai":
            if not self.config.openai_api_key:
                raise ValueError("OpenAI API key not configured")
            self._client = OpenAI(api_key=self.config.openai_api_key)
        else:
            raise ValueError(f"Unsupported AI provider: {self.config.ai_provider}")

    def generate_text(
        self,
        prompt: str,
        system_message: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None
    ) -> str:
        """Generate text from prompt"""
        if self.config.ai_provider == "gemini":
            return self._generate_gemini(prompt, system_message, temperature, max_tokens)
        elif self.config.ai_provider == "openai":
            return self._generate_openai(prompt, system_message, temperature, max_tokens)
        else:
            raise ValueError(f"Unsupported provider: {self.config.ai_provider}")

    def _generate_gemini(
        self, prompt: str, system_message: Optional[str], temperature: float, max_tokens: Optional[int]
    ) -> str:
        """Generate using Gemini"""
        full_prompt = prompt
        if system_message:
            full_prompt = f"{system_message}\n\n{prompt}"

        response = self._client.generate_content(
            full_prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens or self.config.ai_max_tokens,
            )
        )
        return response.text

    def _generate_openai(
        self, prompt: str, system_message: Optional[str], temperature: float, max_tokens: Optional[int]
    ) -> str:
        """Generate using OpenAI"""
        messages = []
        if system_message:
            messages.append({"role": "system", "content": system_message})
        messages.append({"role": "user", "content": prompt})

        response = self._client.chat.completions.create(
            model=self.config.ai_model or "gpt-4",
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens or self.config.ai_max_tokens
        )
        return response.choices[0].message.content

    def analyze_vulnerability(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze vulnerability using AI"""
        # Build analysis prompt
        prompt = self._build_vulnerability_analysis_prompt(vulnerability_data)

        # Generate analysis
        response = self.generate_text(
            prompt=prompt,
            system_message="You are a cybersecurity expert analyzing vulnerabilities. Provide structured, actionable analysis.",
            temperature=0.3  # Lower temperature for more consistent results
        )

        # Parse response into structured format
        return self._parse_vulnerability_analysis(response)

    def _build_vulnerability_analysis_prompt(self, vuln_data: Dict[str, Any]) -> str:
        """Build prompt for vulnerability analysis"""
        name = vuln_data.get('name', 'Unknown')
        description = vuln_data.get('description', '')
        component = vuln_data.get('component', '')

        prompt = f"""Analyze this security vulnerability:

**Vulnerability Name:** {name}
**Affected Component:** {component}
**Description:** {description}

Please provide:
1. **Severity**: (Critical/High/Medium/Low/Info)
2. **Category**: (e.g., Injection, XSS, Authentication, etc.)
3. **Risk Assessment**: Brief explanation of the risk
4. **Remediation Steps**: Specific actionable steps to fix

Format your response as:
SEVERITY: <level>
CATEGORY: <type>
RISK: <explanation>
REMEDIATION:
- Step 1
- Step 2
- Step 3
"""
        return prompt

    def _parse_vulnerability_analysis(self, response: str) -> Dict[str, Any]:
        """Parse AI response into structured format"""
        lines = response.strip().split('\n')
        result = {
            'severity': 'Medium',  # Default
            'category': 'Unknown',
            'risk_assessment': '',
            'recommendations': []
        }

        current_section = None
        for line in lines:
            line = line.strip()
            if line.startswith('SEVERITY:'):
                result['severity'] = line.split(':', 1)[1].strip()
            elif line.startswith('CATEGORY:'):
                result['category'] = line.split(':', 1)[1].strip()
            elif line.startswith('RISK:'):
                result['risk_assessment'] = line.split(':', 1)[1].strip()
                current_section = 'risk'
            elif line.startswith('REMEDIATION:'):
                current_section = 'remediation'
            elif line.startswith('-') and current_section == 'remediation':
                result['recommendations'].append(line.lstrip('- ').strip())
            elif current_section == 'risk' and line and not line.startswith('REMEDIATION:'):
                result['risk_assessment'] += ' ' + line

        return result
