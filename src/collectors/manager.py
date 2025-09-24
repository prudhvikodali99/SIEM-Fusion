"""
Collector Manager for SIEM-Fusion
Manages multiple log collectors and coordinates data collection
"""

import asyncio
import logging
from typing import Dict, List, AsyncGenerator
from datetime import datetime

from .syslog_collector import SyslogCollector
from .mysql_collector import MySQLCollector
from .windows_collector import WindowsEventCollector
from src.database.models import LogEntry
from src.data.dataset_loader import dataset_loader

class CollectorManager:
    """Manages multiple log collectors and dataset loading"""
    
    def __init__(self, use_datasets: bool = True):
        self.collectors: Dict[str, any] = {}
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.use_datasets = use_datasets
        
        # Initialize collectors
        self._initialize_collectors()
    
    def _initialize_collectors(self):
        """Initialize all available collectors"""
        try:
            # Syslog Collector with config
            syslog_config = {'host': '0.0.0.0', 'port': 514, 'enabled': True}
            self.collectors['syslog'] = SyslogCollector(syslog_config)
            self.logger.info("✅ Syslog collector initialized")
            
            # MySQL Collector with config
            mysql_config = {'host': 'localhost', 'port': 3306, 'enabled': True}
            self.collectors['mysql'] = MySQLCollector(mysql_config)
            self.logger.info("✅ MySQL collector initialized")
            
            # Windows Event Collector with config
            windows_config = {'enabled': True}
            self.collectors['windows'] = WindowsEventCollector(windows_config)
            self.logger.info("✅ Windows Event collector initialized")
            
            if self.use_datasets:
                self.logger.info("✅ Dataset loader enabled for security datasets")
            
        except Exception as e:
            self.logger.error(f"❌ Error initializing collectors: {e}")
    
    async def start_collection(self):
        """Start all collectors"""
        self.running = True
        self.logger.info("🚀 Starting log collection from all sources...")
        
        tasks = []
        for name, collector in self.collectors.items():
            if hasattr(collector, 'start'):
                task = asyncio.create_task(collector.start())
                tasks.append(task)
                self.logger.info(f"📡 Started {name} collector")
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def stop_collection(self):
        """Stop all collectors"""
        self.running = False
        self.logger.info("🛑 Stopping log collection...")
        
        for name, collector in self.collectors.items():
            if hasattr(collector, 'stop'):
                await collector.stop()
                self.logger.info(f"⏹️ Stopped {name} collector")
    
    async def collect_all_logs(self) -> AsyncGenerator[LogEntry, None]:
        """Collect logs from all sources including datasets"""
        self.logger.info("🔄 Starting log collection from all collectors and datasets...")
        
        # First, load dataset entries if enabled
        if self.use_datasets:
            self.logger.info("📊 Loading security datasets...")
            dataset_count = 0
            async for log_entry in dataset_loader.load_all_datasets():
                dataset_count += 1
                yield log_entry
                
                # Add delay every 50 entries to prevent overwhelming
                if dataset_count % 50 == 0:
                    await asyncio.sleep(0.5)
                    self.logger.info(f"📈 Processed {dataset_count} dataset entries...")
            
            self.logger.info(f"✅ Dataset loading complete: {dataset_count} entries")
        
        # Then collect from live collectors
        for name, collector in self.collectors.items():
            if hasattr(collector, 'collect_logs'):
                try:
                    async for log_entry in collector.collect_logs():
                        self.logger.debug(f"📥 Collected log from {name}: {log_entry.id}")
                        yield log_entry
                except Exception as e:
                    self.logger.error(f"❌ Error collecting from {name}: {e}")
    
    async def _collect_from_source(self, source_name: str, collector) -> AsyncGenerator[LogEntry, None]:
        """Collect logs from a specific source"""
        try:
            async for log_entry in collector.collect_logs():
                self.logger.debug(f"📥 Collected log from {source_name}: {log_entry.id}")
                yield log_entry
        except Exception as e:
            self.logger.error(f"❌ Error collecting from {source_name}: {e}")
    
    async def load_datasets_only(self) -> AsyncGenerator[LogEntry, None]:
        """Load only dataset entries (useful for testing)"""
        self.logger.info("📊 Loading security datasets only...")
        
        async for log_entry in dataset_loader.load_all_datasets():
            yield log_entry
    
    def get_collector_status(self) -> Dict[str, bool]:
        """Get status of all collectors"""
        status = {}
        for name, collector in self.collectors.items():
            if hasattr(collector, 'is_running'):
                status[name] = collector.is_running()
            else:
                status[name] = True  # Assume running if no status method
        
        # Add dataset loader status
        status['datasets'] = self.use_datasets
        return status
    
    def get_collector_stats(self) -> Dict[str, Dict]:
        """Get statistics from all collectors"""
        stats = {}
        for name, collector in self.collectors.items():
            if hasattr(collector, 'get_stats'):
                stats[name] = collector.get_stats()
            else:
                stats[name] = {"status": "unknown"}
        
        # Add dataset stats
        stats['datasets'] = {
            "enabled": self.use_datasets,
            "status": "active" if self.use_datasets else "disabled"
        }
        return stats
