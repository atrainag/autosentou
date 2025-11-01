import os
from enum import Enum
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


class AIProvider(Enum):
    GEMINI = "gemini"
    OPENAI = "openai"
    DEEPSEEK = "deepseek"
    OLLAMA = "ollama"


class AIConfig:
    """Configuration for AI services."""
    
    def __init__(self):
        # AI Provider Selection
        self.provider = AIProvider(os.getenv('AI_PROVIDER', 'gemini'))
        
        # API Keys
        self.gemini_api_key = os.getenv('GEMINI_API_KEY', '')
        self.openai_api_key = os.getenv('OPENAI_API_KEY', '')
        self.deepseek_api_key = os.getenv('DEEPSEEK_API_KEY', '')
        
        # Ollama Configuration
        self.ollama_base_url = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
        self.ollama_model = os.getenv('OLLAMA_MODEL', 'llama2')
        
        # Embedding Model
        self.embedding_model = os.getenv('EMBEDDING_MODEL', 'BAAI/bge-large-en-v1.5')
        
        # ChromaDB Configuration
        self.chroma_persist_directory = os.getenv('CHROMA_PERSIST_DIR', './chroma_db')
        self.chroma_collection_name = os.getenv('CHROMA_COLLECTION', 'pentest_vulns')
        
        # Model Parameters
        self.temperature = float(os.getenv('AI_TEMPERATURE', '0.7'))
        self.max_tokens = int(os.getenv('AI_MAX_TOKENS', '2000'))
        
        # Browser-use Configuration
        self.browser_headless = os.getenv('BROWSER_HEADLESS', 'true').lower() == 'true'
        self.browser_timeout = int(os.getenv('BROWSER_TIMEOUT', '30000'))
    
    def validate(self) -> bool:
        """Validate configuration based on selected provider."""
        if self.provider == AIProvider.GEMINI:
            return bool(self.gemini_api_key)
        elif self.provider == AIProvider.OPENAI:
            return bool(self.openai_api_key)
        elif self.provider == AIProvider.DEEPSEEK:
            return bool(self.deepseek_api_key)
        elif self.provider == AIProvider.OLLAMA:
            return bool(self.ollama_base_url)
        return False


# Global AI configuration instance
ai_config = AIConfig()