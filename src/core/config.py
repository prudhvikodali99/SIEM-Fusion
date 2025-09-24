import os
import yaml
from typing import Dict, Any
from pathlib import Path

class Config:
    """Configuration manager for SIEM-Fusion"""
    
    def __init__(self, config_path: str = None):
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent / "config.yaml"
        
        self.config_path = config_path
        self._config = self._load_config()
        self._substitute_env_vars()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as file:
                return yaml.safe_load(file)
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML configuration: {e}")
    
    def _substitute_env_vars(self):
        """Substitute environment variables in configuration"""
        def substitute_recursive(obj):
            if isinstance(obj, dict):
                return {k: substitute_recursive(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [substitute_recursive(item) for item in obj]
            elif isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
                env_var = obj[2:-1]
                return os.getenv(env_var, obj)
            return obj
        
        self._config = substitute_recursive(self._config)
    
    def get(self, key_path: str, default=None):
        """Get configuration value using dot notation (e.g., 'siem_fusion.llm_models.anomaly_detection')"""
        keys = key_path.split('.')
        value = self._config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def get_llm_config(self, model_name: str) -> Dict[str, Any]:
        """Get LLM configuration for a specific model"""
        return self.get(f"siem_fusion.llm_models.{model_name}", {})
    
    def get_api_key(self, provider: str) -> str:
        """Get API key for a specific provider"""
        key = self.get(f"siem_fusion.api_keys.{provider}_api_key")
        if not key:
            raise ValueError(f"API key not found for provider: {provider}")
        return key
    
    @property
    def data_collector_config(self) -> Dict[str, Any]:
        return self.get("siem_fusion.data_collector", {})
    
    @property
    def processing_config(self) -> Dict[str, Any]:
        return self.get("siem_fusion.processing", {})
    
    @property
    def dashboard_config(self) -> Dict[str, Any]:
        return self.get("siem_fusion.dashboard", {})
    
    @property
    def database_url(self) -> str:
        return self.get("siem_fusion.database.url", "sqlite:///siem_fusion.db")
    
    @property
    def redis_config(self) -> Dict[str, Any]:
        return self.get("siem_fusion.redis", {})

# Global configuration instance
config = Config()
