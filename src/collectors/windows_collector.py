import asyncio
import json
import subprocess
from datetime import datetime
from typing import AsyncGenerator, List
from src.collectors.base import BaseCollector
from src.models.schemas import RawLogEntry, LogSource

class WindowsEventCollector(BaseCollector):
    """Collector for Windows Event Logs"""
    
    def __init__(self, config: dict):
        super().__init__(config)
        self.log_types = config.get('log_types', ['Security', 'System', 'Application'])
        self.running = False
        self.poll_interval = config.get('poll_interval', 60)  # seconds
        self.last_event_ids = {}  # Track last event ID for each log type
    
    async def start(self):
        """Start the Windows Event collector"""
        if not self.enabled:
            return
        
        # Initialize last event IDs for each log type
        for log_type in self.log_types:
            self.last_event_ids[log_type] = await self._get_latest_event_id(log_type)
        
        self.running = True
        print(f"Windows Event collector started for logs: {', '.join(self.log_types)}")
    
    async def stop(self):
        """Stop the Windows Event collector"""
        self.running = False
        print("Windows Event collector stopped")
    
    async def collect_logs(self) -> AsyncGenerator[RawLogEntry, None]:
        """Collect Windows Event logs"""
        while self.running:
            try:
                for log_type in self.log_types:
                    events = await self._fetch_new_events(log_type)
                    for event_data in events:
                        log_entry = self._create_log_entry(event_data, log_type)
                        yield log_entry
                
                # Wait before next poll
                await asyncio.sleep(self.poll_interval)
                
            except Exception as e:
                print(f"Error collecting Windows Event logs: {e}")
                await asyncio.sleep(5)  # Wait before retrying
    
    async def _get_latest_event_id(self, log_type: str) -> int:
        """Get the latest event ID for a log type"""
        try:
            # PowerShell command to get the latest event ID
            cmd = [
                'powershell', '-Command',
                f"Get-WinEvent -LogName '{log_type}' -MaxEvents 1 | Select-Object -ExpandProperty Id"
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0 and stdout:
                return int(stdout.decode().strip())
            else:
                return 0
        
        except Exception as e:
            print(f"Error getting latest event ID for {log_type}: {e}")
            return 0
    
    async def _fetch_new_events(self, log_type: str) -> List[dict]:
        """Fetch new events from Windows Event Log"""
        try:
            last_id = self.last_event_ids.get(log_type, 0)
            
            # PowerShell command to get events newer than last_id
            cmd = [
                'powershell', '-Command',
                f"""
                Get-WinEvent -LogName '{log_type}' -MaxEvents 100 | 
                Where-Object {{ $_.Id -gt {last_id} }} | 
                ConvertTo-Json -Depth 3
                """
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0 and stdout:
                output = stdout.decode().strip()
                if output:
                    # Parse JSON output
                    events_data = json.loads(output)
                    if isinstance(events_data, dict):
                        events_data = [events_data]  # Single event
                    
                    # Update last event ID
                    if events_data:
                        max_id = max(event.get('Id', 0) for event in events_data)
                        self.last_event_ids[log_type] = max_id
                    
                    return events_data
            
            return []
        
        except Exception as e:
            print(f"Error fetching Windows events for {log_type}: {e}")
            return []
    
    def _create_log_entry(self, event_data: dict, log_type: str) -> RawLogEntry:
        """Create RawLogEntry from Windows Event data"""
        # Extract relevant information from Windows Event
        event_id = event_data.get('Id', 0)
        level_display_name = event_data.get('LevelDisplayName', 'Information')
        time_created = event_data.get('TimeCreated')
        
        # Parse timestamp
        if time_created:
            try:
                timestamp = datetime.fromisoformat(time_created.replace('Z', '+00:00'))
            except:
                timestamp = datetime.now()
        else:
            timestamp = datetime.now()
        
        # Extract user and process information
        user = None
        process = None
        
        # Try to extract user from security descriptor
        security_data = event_data.get('UserId', {})
        if security_data:
            user = str(security_data)
        
        # Extract process information from event data
        process_id = event_data.get('ProcessId')
        if process_id:
            process = f"PID:{process_id}"
        
        return RawLogEntry(
            id=f"win_{log_type}_{event_id}_{int(timestamp.timestamp())}",
            source=LogSource.WINDOWS_EVENT,
            timestamp=timestamp,
            raw_data=json.dumps(event_data),
            user=user,
            event_type=f"windows_{log_type.lower()}_{event_id}",
            log_metadata={
                'log_type': log_type,
                'event_id': event_id,
                'level': level_display_name,
                'provider_name': event_data.get('ProviderName'),
                'task_display_name': event_data.get('TaskDisplayName'),
                'opcode_display_name': event_data.get('OpcodeDisplayName'),
                'keywords': event_data.get('Keywords'),
                'process_id': process_id,
                'thread_id': event_data.get('ThreadId'),
                'computer_name': event_data.get('MachineName')
            }
        )
    
    def health_check(self) -> bool:
        """Check if the Windows Event collector is healthy"""
        return self.running
