from abc import ABC, abstractmethod
from typing import AsyncGenerator, List
from src.models.schemas import RawLogEntry

class BaseCollector(ABC):
    """Base class for all log collectors"""
    
    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get('enabled', False)
    
    @abstractmethod
    async def start(self):
        """Start the collector"""
        pass
    
    @abstractmethod
    async def stop(self):
        """Stop the collector"""
        pass
    
    @abstractmethod
    async def collect_logs(self) -> AsyncGenerator[RawLogEntry, None]:
        """Collect logs from the source"""
        pass
    
    @abstractmethod
    def health_check(self) -> bool:
        """Check if the collector is healthy"""
        pass
