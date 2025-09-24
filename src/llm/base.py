from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from src.core.config import config

class BaseLLM(ABC):
    """Base class for all LLM processors"""
    
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.config = config.get_llm_config(model_name)
        self.provider = self.config.get('provider', 'openai')
        self.model = self.config.get('model', 'gpt-4')
        self.temperature = self.config.get('temperature', 0.1)
        self.max_tokens = self.config.get('max_tokens', 1000)
        
        # Initialize Gemini client (only provider we're using)
        if self.provider == 'gemini':
            try:
                import google.generativeai as genai
                api_key = config.get_api_key('gemini')
                genai.configure(api_key=api_key)
                self.client = genai.GenerativeModel(self.model)
            except ImportError:
                raise ValueError("google-generativeai package required. Install with: pip install google-generativeai")
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}. Only 'gemini' is supported in this free version.")
    
    async def generate_response(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate response from Gemini LLM"""
        try:
            # Only Gemini is supported in this free version
            if self.provider == 'gemini':
                full_prompt = prompt
                if system_prompt:
                    full_prompt = f"{system_prompt}\n\n{prompt}"
                
                response = self.client.generate_content(
                    full_prompt,
                    generation_config={
                        "temperature": self.temperature,
                        "max_output_tokens": self.max_tokens
                    }
                )
                return response.text
            else:
                raise ValueError(f"Provider {self.provider} not supported. Only 'gemini' is available in free version.")
        
        except Exception as e:
            print(f"Error generating LLM response: {e}")
            raise
    
    @abstractmethod
    async def process(self, input_data: Any) -> Any:
        """Process input data and return result"""
        pass
    
    @abstractmethod
    def get_system_prompt(self) -> str:
        """Get the system prompt for this LLM"""
        pass
