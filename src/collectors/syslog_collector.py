import asyncio
import socket
import json
from datetime import datetime
from typing import AsyncGenerator
from src.collectors.base import BaseCollector
from src.models.schemas import RawLogEntry, LogSource

class SyslogCollector(BaseCollector):
    """Collector for Syslog messages"""
    
    def __init__(self, config: dict):
        super().__init__(config)
        self.host = config.get('host', '0.0.0.0')
        self.port = config.get('port', 514)
        self.server = None
        self.running = False
        self.log_queue = asyncio.Queue()
    
    async def start(self):
        """Start the syslog server"""
        if not self.enabled:
            return
        
        self.server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        self.running = True
        print(f"Syslog collector started on {self.host}:{self.port}")
    
    async def stop(self):
        """Stop the syslog server"""
        self.running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        print("Syslog collector stopped")
    
    async def _handle_client(self, reader, writer):
        """Handle incoming syslog messages"""
        try:
            while self.running:
                data = await reader.read(4096)
                if not data:
                    break
                
                message = data.decode('utf-8', errors='ignore').strip()
                if message:
                    log_entry = self._parse_syslog_message(message)
                    await self.log_queue.put(log_entry)
        
        except Exception as e:
            print(f"Error handling syslog client: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    def _parse_syslog_message(self, message: str) -> RawLogEntry:
        """Parse syslog message into RawLogEntry"""
        # Basic syslog parsing - can be enhanced for RFC3164/RFC5424
        parts = message.split(' ', 5)
        
        # Extract basic information
        source_ip = None
        event_type = "syslog"
        
        # Try to extract IP addresses from the message
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, message)
        if ips:
            source_ip = ips[0]
        
        return RawLogEntry(
            source=LogSource.SYSLOG,
            timestamp=datetime.now(),
            raw_data=message,
            source_ip=source_ip,
            event_type=event_type,
            log_metadata={
                'facility': parts[0] if len(parts) > 0 else None,
                'severity': parts[1] if len(parts) > 1 else None,
                'hostname': parts[2] if len(parts) > 2 else None,
                'process': parts[3] if len(parts) > 3 else None
            }
        )
    
    async def collect_logs(self) -> AsyncGenerator[RawLogEntry, None]:
        """Yield collected log entries"""
        while self.running:
            try:
                log_entry = await asyncio.wait_for(self.log_queue.get(), timeout=1.0)
                yield log_entry
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"Error collecting syslog: {e}")
                break
    
    def health_check(self) -> bool:
        """Check if the syslog collector is healthy"""
        return self.running and self.server is not None
