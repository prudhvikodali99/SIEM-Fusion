import re
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from src.models.schemas import RawLogEntry, NormalizedLogEntry, LogSource

class LogNormalizer:
    """Normalizes raw log entries into a standardized schema"""
    
    def __init__(self):
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.port_pattern = re.compile(r':(\d{1,5})\b')
        self.user_patterns = {
            'windows': re.compile(r'(?:User|Account|Username)[:=]\s*([^\s,;]+)', re.IGNORECASE),
            'linux': re.compile(r'(?:user|uid)[:=]\s*([^\s,;]+)', re.IGNORECASE),
            'general': re.compile(r'(?:login|auth|user)[:=]\s*([^\s,;]+)', re.IGNORECASE)
        }
        self.process_patterns = {
            'windows': re.compile(r'(?:Process|ProcessName)[:=]\s*([^\s,;]+)', re.IGNORECASE),
            'linux': re.compile(r'(?:process|cmd|command)[:=]\s*([^\s,;]+)', re.IGNORECASE)
        }
    
    def normalize(self, raw_log: RawLogEntry) -> NormalizedLogEntry:
        """Normalize a raw log entry"""
        # Generate unique ID if not present
        log_id = raw_log.id or str(uuid.uuid4())
        
        # Extract normalized fields based on source type
        if raw_log.source == LogSource.SYSLOG:
            return self._normalize_syslog(raw_log, log_id)
        elif raw_log.source == LogSource.MYSQL:
            return self._normalize_mysql(raw_log, log_id)
        elif raw_log.source == LogSource.WINDOWS_EVENT:
            return self._normalize_windows_event(raw_log, log_id)
        else:
            return self._normalize_generic(raw_log, log_id)
    
    def _normalize_syslog(self, raw_log: RawLogEntry, log_id: str) -> NormalizedLogEntry:
        """Normalize syslog entries"""
        message = raw_log.raw_data
        
        # Extract IPs
        ips = self.ip_pattern.findall(message)
        source_ip = raw_log.source_ip or (ips[0] if ips else None)
        destination_ip = ips[1] if len(ips) > 1 else None
        
        # Extract ports
        ports = self.port_pattern.findall(message)
        port = int(ports[0]) if ports else None
        
        # Extract user
        user = raw_log.user or self._extract_user(message)
        
        # Extract process
        process = self._extract_process(message)
        
        # Determine event type and severity
        event_type = self._determine_event_type(message, raw_log.event_type)
        severity = self._determine_severity(message, raw_log.log_metadata.get('severity') if raw_log.log_metadata else None)
        
        # Generate tags
        tags = self._generate_tags(message, raw_log.source)
        
        return NormalizedLogEntry(
            id=log_id,
            source=raw_log.source,
            timestamp=raw_log.timestamp,
            event_type=event_type,
            source_ip=source_ip,
            destination_ip=destination_ip,
            user=user,
            process=process,
            port=port,
            message=message,
            severity=severity,
            tags=tags,
            log_metadata=raw_log.log_metadata
        )
    
    def _normalize_mysql(self, raw_log: RawLogEntry, log_id: str) -> NormalizedLogEntry:
        """Normalize MySQL log entries"""
        # MySQL logs are already somewhat structured
        message = raw_log.log_metadata.get('message', raw_log.raw_data)
        
        return NormalizedLogEntry(
            id=log_id,
            source=raw_log.source,
            timestamp=raw_log.timestamp,
            event_type=raw_log.event_type or 'database_event',
            source_ip=raw_log.source_ip,
            destination_ip=raw_log.destination_ip,
            user=raw_log.user,
            message=message,
            severity=raw_log.log_metadata.get('severity', 'info'),
            tags=self._generate_tags(message, raw_log.source),
            log_metadata=raw_log.log_metadata
        )
    
    def _normalize_windows_event(self, raw_log: RawLogEntry, log_id: str) -> NormalizedLogEntry:
        """Normalize Windows Event log entries"""
        try:
            # Parse the JSON data
            event_data = json.loads(raw_log.raw_data)
        except:
            event_data = {}
        
        # Extract relevant fields
        event_id = raw_log.log_metadata.get('event_id', 0) if raw_log.log_metadata else 0
        log_type = raw_log.log_metadata.get('log_type', 'Unknown') if raw_log.log_metadata else 'Unknown'
        level = raw_log.log_metadata.get('level', 'Information') if raw_log.log_metadata else 'Information'
        
        # Create meaningful message
        message = self._create_windows_message(event_data, event_id, log_type)
        
        # Extract user and process info
        user = raw_log.user or event_data.get('UserId')
        process_id = raw_log.log_metadata.get('process_id') if raw_log.log_metadata else None
        process = f"PID:{process_id}" if process_id else None
        
        # Determine severity based on Windows event level
        severity = self._map_windows_severity(level)
        
        # Generate event type
        event_type = f"windows_{log_type.lower()}_{event_id}"
        
        # Generate tags
        tags = self._generate_windows_tags(event_data, log_type, level)
        
        return NormalizedLogEntry(
            id=log_id,
            source=raw_log.source,
            timestamp=raw_log.timestamp,
            event_type=event_type,
            user=user,
            process=process,
            message=message,
            severity=severity,
            tags=tags,
            log_metadata=raw_log.log_metadata
        )
    
    def _normalize_generic(self, raw_log: RawLogEntry, log_id: str) -> NormalizedLogEntry:
        """Generic normalization for unknown log types"""
        message = raw_log.raw_data
        
        return NormalizedLogEntry(
            id=log_id,
            source=raw_log.source,
            timestamp=raw_log.timestamp,
            event_type=raw_log.event_type or 'generic_event',
            source_ip=raw_log.source_ip,
            destination_ip=raw_log.destination_ip,
            user=raw_log.user,
            message=message,
            severity='info',
            tags=self._generate_tags(message, raw_log.source),
            log_metadata=raw_log.log_metadata
        )
    
    def _extract_user(self, message: str) -> Optional[str]:
        """Extract user information from log message"""
        for pattern in self.user_patterns.values():
            match = pattern.search(message)
            if match:
                return match.group(1)
        return None
    
    def _extract_process(self, message: str) -> Optional[str]:
        """Extract process information from log message"""
        for pattern in self.process_patterns.values():
            match = pattern.search(message)
            if match:
                return match.group(1)
        return None
    
    def _determine_event_type(self, message: str, existing_type: Optional[str]) -> str:
        """Determine event type based on message content"""
        if existing_type:
            return existing_type
        
        message_lower = message.lower()
        
        # Authentication events
        if any(keyword in message_lower for keyword in ['login', 'auth', 'logon', 'signin']):
            return 'authentication'
        
        # Network events
        if any(keyword in message_lower for keyword in ['connection', 'network', 'tcp', 'udp']):
            return 'network'
        
        # File system events
        if any(keyword in message_lower for keyword in ['file', 'directory', 'folder', 'path']):
            return 'filesystem'
        
        # Process events
        if any(keyword in message_lower for keyword in ['process', 'execution', 'command']):
            return 'process'
        
        # Security events
        if any(keyword in message_lower for keyword in ['security', 'alert', 'threat', 'malware']):
            return 'security'
        
        return 'general'
    
    def _determine_severity(self, message: str, existing_severity: Optional[str]) -> str:
        """Determine severity based on message content"""
        if existing_severity:
            return existing_severity.lower()
        
        message_lower = message.lower()
        
        # Critical indicators
        if any(keyword in message_lower for keyword in ['critical', 'fatal', 'emergency', 'panic']):
            return 'critical'
        
        # High severity indicators
        if any(keyword in message_lower for keyword in ['error', 'fail', 'alert', 'attack', 'breach']):
            return 'high'
        
        # Medium severity indicators
        if any(keyword in message_lower for keyword in ['warning', 'warn', 'suspicious', 'anomaly']):
            return 'medium'
        
        # Low severity (default)
        return 'low'
    
    def _generate_tags(self, message: str, source) -> List[str]:
        """Generate tags based on message content and source"""
        # Handle both string and LogSource enum
        source_tag = source.value if hasattr(source, 'value') else str(source)
        tags = [source_tag]
        message_lower = message.lower()
        
        # Add content-based tags
        tag_keywords = {
            'authentication': ['login', 'auth', 'password', 'credential'],
            'network': ['connection', 'tcp', 'udp', 'http', 'https'],
            'security': ['security', 'threat', 'malware', 'virus', 'attack'],
            'filesystem': ['file', 'directory', 'folder', 'disk'],
            'process': ['process', 'execution', 'command', 'service'],
            'database': ['sql', 'database', 'query', 'table'],
            'web': ['http', 'web', 'browser', 'url', 'request']
        }
        
        for tag, keywords in tag_keywords.items():
            if any(keyword in message_lower for keyword in keywords):
                tags.append(tag)
        
        return list(set(tags))  # Remove duplicates
    
    def _create_windows_message(self, event_data: Dict[str, Any], event_id: int, log_type: str) -> str:
        """Create a meaningful message for Windows events"""
        # Common Windows Event IDs and their meanings
        event_descriptions = {
            4624: "Successful logon",
            4625: "Failed logon attempt",
            4634: "Account logoff",
            4648: "Logon with explicit credentials",
            4672: "Special privileges assigned",
            4720: "User account created",
            4726: "User account deleted",
            4740: "User account locked",
            4767: "User account unlocked",
            1102: "Audit log cleared",
            7045: "Service installed",
            4688: "Process created",
            4689: "Process terminated"
        }
        
        base_message = event_descriptions.get(event_id, f"Windows {log_type} Event {event_id}")
        
        # Add additional context if available
        context_parts = []
        
        if 'TargetUserName' in event_data:
            context_parts.append(f"User: {event_data['TargetUserName']}")
        
        if 'WorkstationName' in event_data:
            context_parts.append(f"Workstation: {event_data['WorkstationName']}")
        
        if 'IpAddress' in event_data:
            context_parts.append(f"IP: {event_data['IpAddress']}")
        
        if context_parts:
            return f"{base_message} - {', '.join(context_parts)}"
        
        return base_message
    
    def _map_windows_severity(self, level: str) -> str:
        """Map Windows event levels to our severity scale"""
        level_mapping = {
            'Critical': 'critical',
            'Error': 'high',
            'Warning': 'medium',
            'Information': 'low',
            'Verbose': 'low'
        }
        return level_mapping.get(level, 'low')
    
    def _generate_windows_tags(self, event_data: Dict[str, Any], log_type: str, level: str) -> List[str]:
        """Generate tags for Windows events"""
        tags = ['windows_event', log_type.lower()]
        
        # Add level-based tag
        tags.append(f"level_{level.lower()}")
        
        # Add event-specific tags based on content
        if 'logon' in str(event_data).lower():
            tags.append('authentication')
        
        if 'process' in str(event_data).lower():
            tags.append('process')
        
        if 'network' in str(event_data).lower():
            tags.append('network')
        
        return tags
