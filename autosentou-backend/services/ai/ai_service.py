import os
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod
import google.generativeai as genai
from openai import OpenAI
import requests
from services.ai.config import AIConfig, AIProvider
import threading
import json


class BaseAIProvider(ABC):
    """Base class for AI providers."""
    
    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> str:
        """Generate text from prompt."""
        pass
    
    @abstractmethod
    def generate_with_context(self, prompt: str, context: str, **kwargs) -> str:
        """Generate text with additional context."""
        pass


class GeminiProvider(BaseAIProvider):
    """Google Gemini AI provider."""
    
    def __init__(self, api_key: str, temperature: float = 0.7, max_tokens: int = 2000):
        genai.configure(api_key=api_key)
        # Use the correct model name - gemini-1.5-flash or gemini-1.5-pro
        try:
            self.model = genai.GenerativeModel('gemini-2.5-flash')
        except:
            # Fallback to older model if available
            try:
                self.model = genai.GenerativeModel('gemini-pro')
            except:
                # Last resort - try gemini-1.5-pro
                self.model = genai.GenerativeModel('gemini-1.5-pro')
        
        self.temperature = temperature
        self.max_tokens = max_tokens
    
    def generate(self, prompt: str, **kwargs) -> str:
        try:
            response = self.model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=kwargs.get('temperature', self.temperature),
                )
            )

            # Handle blocked responses
            if response.prompt_feedback.block_reason:
                print(f"Gemini blocked response: {response.prompt_feedback.block_reason}")
                return json.dumps({
                    "error": "Content blocked by safety filters",
                    "fallback": True,
                    "reason": str(response.prompt_feedback.block_reason)
                })
            
            # Handle multi-part responses
            if not response.parts:
                print(f"Gemini returned empty response")
                return json.dumps({
                    "error": "Empty response from AI",
                    "fallback": True
                })
            
            # Extract text from all parts
            text_parts = []
            for part in response.parts:
                if hasattr(part, 'text'):
                    text_parts.append(part.text)
            
            if not text_parts:
                print(f"No text parts in response")
                return json.dumps({
                    "error": "No text in AI response",
                    "fallback": True
                })
            
            return ''.join(text_parts)
            
        except Exception as e:
            print(f"Gemini generation error: {e}")
            import traceback
            print(traceback.format_exc())
            # Return fallback response
            return json.dumps({
                "error": "AI generation failed",
                "fallback": True,
                "message": str(e)
            })
    
    def generate_with_context(self, prompt: str, context: str, **kwargs) -> str:
        full_prompt = f"Context:\n{context}\n\nTask:\n{prompt}"
        return self.generate(full_prompt, **kwargs)


class OpenAIProvider(BaseAIProvider):
    """OpenAI GPT provider."""
    
    def __init__(self, api_key: str, temperature: float = 0.7, max_tokens: int = 2000):
        self.client = OpenAI(api_key=api_key)
        self.model = "gpt-4-turbo-preview"
        self.temperature = temperature
        self.max_tokens = max_tokens
    
    def generate(self, prompt: str, **kwargs) -> str:
        try:
            response = self.client.chat.completions.create(
                model=kwargs.get('model', self.model),
                messages=[{"role": "user", "content": prompt}],
                temperature=kwargs.get('temperature', self.temperature),
                max_tokens=kwargs.get('max_tokens', self.max_tokens),
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"OpenAI generation error: {e}")
            return json.dumps({"error": "AI generation failed", "fallback": True})
    
    def generate_with_context(self, prompt: str, context: str, **kwargs) -> str:
        try:
            response = self.client.chat.completions.create(
                model=kwargs.get('model', self.model),
                messages=[
                    {"role": "system", "content": f"Context: {context}"},
                    {"role": "user", "content": prompt}
                ],
                temperature=kwargs.get('temperature', self.temperature),
                max_tokens=kwargs.get('max_tokens', self.max_tokens),
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"OpenAI generation error: {e}")
            return json.dumps({"error": "AI generation failed", "fallback": True})


class DeepSeekProvider(BaseAIProvider):
    """DeepSeek AI provider."""
    
    def __init__(self, api_key: str, temperature: float = 0.7, max_tokens: int = 2000):
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com/v1"
        )
        self.model = "deepseek-chat"
        self.temperature = temperature
        self.max_tokens = max_tokens
    
    def generate(self, prompt: str, **kwargs) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=kwargs.get('temperature', self.temperature),
                max_tokens=kwargs.get('max_tokens', self.max_tokens),
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"DeepSeek generation error: {e}")
            return json.dumps({"error": "AI generation failed", "fallback": True})
    
    def generate_with_context(self, prompt: str, context: str, **kwargs) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": f"Context: {context}"},
                    {"role": "user", "content": prompt}
                ],
                temperature=kwargs.get('temperature', self.temperature),
                max_tokens=kwargs.get('max_tokens', self.max_tokens),
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"DeepSeek generation error: {e}")
            return json.dumps({"error": "AI generation failed", "fallback": True})


class OllamaProvider(BaseAIProvider):
    """Ollama local AI provider."""
    
    def __init__(self, base_url: str, model: str, temperature: float = 0.7, max_tokens: int = 2000):
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
    
    def generate(self, prompt: str, **kwargs) -> str:
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": kwargs.get('model', self.model),
                    "prompt": prompt,
                    "temperature": kwargs.get('temperature', self.temperature),
                    "max_tokens": kwargs.get('max_tokens', self.max_tokens),
                    "stream": False
                },
                timeout=120
            )
            response.raise_for_status()
            return response.json().get('response', '')
        except Exception as e:
            print(f"Ollama generation error: {e}")
            return json.dumps({"error": "AI generation failed", "fallback": True})
    
    def generate_with_context(self, prompt: str, context: str, **kwargs) -> str:
        full_prompt = f"Context:\n{context}\n\nTask:\n{prompt}"
        return self.generate(full_prompt, **kwargs)


class AIService:
    """Main AI service with provider abstraction and lazy initialization."""
    
    _instance = None
    _lock = threading.Lock()
    _initialized = False
    
    def __new__(cls, *args, **kwargs):
        """Singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, config: AIConfig):
        if self._initialized:
            return
            
        with self._lock:
            if self._initialized:
                return
                
            self.config = config
            self.provider = None
            self._initialized = True
    
    def _ensure_provider(self):
        """Lazy initialization of AI provider."""
        if self.provider is not None:
            return
        
        with self._lock:
            if self.provider is not None:
                return
            
            try:
                self.provider = self._initialize_provider()
                print(f"✓ AI Provider initialized: {self.config.provider.value}")
            except Exception as e:
                print(f"✗ Failed to initialize AI provider: {e}")
                # Create a fallback provider that returns structured JSON
                self.provider = self._create_fallback_provider()
    
    def _create_fallback_provider(self):
        """Create a fallback provider when real AI is unavailable."""
        class FallbackProvider(BaseAIProvider):
            def generate(self, prompt: str, **kwargs) -> str:
                return json.dumps({
                    "error": "AI provider unavailable",
                    "fallback": True,
                    "vulnerabilities": [],
                    "summary": "AI analysis unavailable - manual review recommended"
                })
            
            def generate_with_context(self, prompt: str, context: str, **kwargs) -> str:
                return self.generate(prompt, **kwargs)
        
        return FallbackProvider()
    
    def _initialize_provider(self) -> BaseAIProvider:
        """Initialize AI provider based on configuration."""
        if self.config.provider == AIProvider.GEMINI:
            return GeminiProvider(
                self.config.gemini_api_key,
                self.config.temperature,
                self.config.max_tokens
            )
        elif self.config.provider == AIProvider.OPENAI:
            return OpenAIProvider(
                self.config.openai_api_key,
                self.config.temperature,
                self.config.max_tokens
            )
        elif self.config.provider == AIProvider.DEEPSEEK:
            return DeepSeekProvider(
                self.config.deepseek_api_key,
                self.config.temperature,
                self.config.max_tokens
            )
        elif self.config.provider == AIProvider.OLLAMA:
            return OllamaProvider(
                self.config.ollama_base_url,
                self.config.ollama_model,
                self.config.temperature,
                self.config.max_tokens
            )
        else:
            raise ValueError(f"Unsupported AI provider: {self.config.provider}")
    
    def generate(self, prompt: str, **kwargs) -> str:
        """Generate text from prompt."""
        self._ensure_provider()
        return self.provider.generate(prompt, **kwargs)
    
    def generate_with_context(self, prompt: str, context: str, **kwargs) -> str:
        """Generate text with additional context."""
        self._ensure_provider()
        return self.provider.generate_with_context(prompt, context, **kwargs)
    
    def analyze_vulnerability(self, service: str, version: str, port: int) -> Dict[str, Any]:
        """Analyze vulnerability for a specific service."""
        self._ensure_provider()
        
        prompt = f"""
You are a cybersecurity expert. Analyze the following service for known vulnerabilities:

Service: {service}
Version: {version}
Port: {port}

Please provide:
1. Known vulnerabilities (CVEs)
2. Severity level (Critical/High/Medium/Low)
3. Brief description of each vulnerability
4. Exploitation difficulty (Easy/Medium/Hard)
5. Recommended mitigation steps

Format your response as JSON with the following structure:
{{
    "vulnerabilities": [
        {{
            "cve_id": "CVE-XXXX-XXXX",
            "severity": "High",
            "description": "...",
            "exploitation_difficulty": "Medium",
            "mitigation": "..."
        }}
    ],
    "overall_risk": "High/Medium/Low",
    "summary": "Brief summary of findings"
}}
"""
        
        response = self.generate(prompt)
        
        # Check if it's a fallback response
        try:
            parsed = json.loads(response)
            if parsed.get('fallback') or parsed.get('error'):
                print(f"AI returned fallback response: {parsed.get('error', 'unknown error')}")
                return {
                    "vulnerabilities": [],
                    "overall_risk": "Unknown",
                    "summary": f"AI analysis unavailable for {service} {version} on port {port}"
                }
            return parsed
        except json.JSONDecodeError:
            # Try to extract JSON from response text
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group())
                except:
                    pass
            
            # Final fallback
            return {
                "vulnerabilities": [],
                "overall_risk": "Unknown",
                "summary": f"Manual review recommended for {service} {version} on port {port}"
            }
    
    def analyze_web_path(self, url: str, status_code: int, content_length: int) -> Dict[str, Any]:
        """Analyze a web path for potential vulnerabilities."""
        self._ensure_provider()
        
        prompt = f"""
You are a web security expert. Analyze the following web path:

URL: {url}
Status Code: {status_code}
Content Length: {content_length}

Determine:
1. Risk level (Critical/High/Medium/Low/Info)
2. Potential vulnerability types (SQLi, XSS, LFI, RFI, Authentication Bypass, etc.)
3. Whether this path should be tested with SQLMap
4. Whether this is a login page that should be brute-forced
5. Whether this exposes sensitive information
6. Specific security concerns

Format response as JSON:
{{
    "risk_level": "High/Medium/Low/Info",
    "vulnerability_types": ["SQLi", "XSS"],
    "test_with_sqlmap": true/false,
    "is_login_page": true/false,
    "exposes_sensitive_info": true/false,
    "security_concerns": ["concern 1", "concern 2"],
    "recommendation": "Detailed recommendation",
    "reason": "Why this path is interesting"
}}
"""
        
        response = self.generate(prompt)
        
        try:
            parsed = json.loads(response)
            if parsed.get('fallback') or parsed.get('error'):
                # Use heuristics fallback
                return {
                    "risk_level": "Info",
                    "vulnerability_types": [],
                    "test_with_sqlmap": '?' in url or 'id=' in url.lower(),
                    "is_login_page": 'login' in url.lower() or 'admin' in url.lower(),
                    "exposes_sensitive_info": any(x in url.lower() for x in ['.bak', '.sql', '.zip', 'backup']),
                    "security_concerns": ["AI analysis unavailable - using heuristics"],
                    "recommendation": "Manual review recommended",
                    "reason": "Automated heuristic analysis"
                }
            return parsed
        except json.JSONDecodeError:
            # Try to extract JSON from response text
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group())
                except:
                    pass
            
            # Fallback with basic heuristics
            return {
                "risk_level": "Info",
                "vulnerability_types": [],
                "test_with_sqlmap": '?' in url or 'id=' in url.lower(),
                "is_login_page": 'login' in url.lower() or 'admin' in url.lower(),
                "exposes_sensitive_info": any(x in url.lower() for x in ['.bak', '.sql', '.zip', 'backup']),
                "security_concerns": [],
                "recommendation": "Manual review recommended",
                "reason": "Automated analysis"
            }
    
    def analyze_login_response(self, response_text: str, status_code: int) -> Dict[str, Any]:
        """Analyze login response for security issues."""
        self._ensure_provider()
        
        prompt = f"""
Analyze this login page response for security vulnerabilities:

Status Code: {status_code}
Response Text: {response_text[:500]}

Check for:
1. Does it reveal if username exists? (Security issue)
2. Does it distinguish between invalid username vs invalid password?
3. Account enumeration vulnerabilities
4. Information disclosure issues
5. Security recommendations

Format as JSON:
{{
    "reveals_username_exists": true/false,
    "distinguishes_errors": true/false,
    "account_enumeration_possible": true/false,
    "security_issues": ["issue 1", "issue 2"],
    "recommendations": ["rec 1", "rec 2"],
    "risk_level": "High/Medium/Low"
}}
"""
        
        response = self.generate(prompt)
        
        try:
            parsed = json.loads(response)
            if parsed.get('fallback') or parsed.get('error'):
                return {
                    "reveals_username_exists": False,
                    "distinguishes_errors": False,
                    "account_enumeration_possible": False,
                    "security_issues": ["AI analysis unavailable"],
                    "recommendations": ["Manual review of login error messages required"],
                    "risk_level": "Unknown"
                }
            return parsed
        except json.JSONDecodeError:
            # Try to extract JSON
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group())
                except:
                    pass
            
            return {
                "reveals_username_exists": False,
                "distinguishes_errors": False,
                "account_enumeration_possible": False,
                "security_issues": ["Unable to analyze - manual review required"],
                "recommendations": ["Review login error messages manually"],
                "risk_level": "Unknown"
            }


# Factory function
def get_ai_service():
    """Get or create AI service instance."""
    from services.ai.config import ai_config
    return AIService(ai_config)


# For backward compatibility
ai_service = None


def init_ai_service():
    """Initialize AI service when needed."""
    global ai_service
    if ai_service is None:
        ai_service = get_ai_service()
    return ai_service
