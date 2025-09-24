import json
import uuid
from datetime import datetime
from typing import List
from src.llm.base import BaseLLM
from src.models.schemas import NormalizedLogEntry, CorrelationResult, Alert, SeverityLevel, AlertStatus

class AlertGenerationLLM(BaseLLM):
    """LLM-4: Decision & Alert Generation - Creates final actionable alerts"""
    
    def __init__(self):
        super().__init__('alert_generation')
    
    def get_system_prompt(self) -> str:
        return """You are an expert security analyst responsible for generating final, actionable security alerts.

Your role is to synthesize all previous analysis (anomaly detection, threat intelligence, contextual correlation) into clear, concise, and actionable alerts for SOC analysts.

For each correlated threat, create an alert with:

1. Clear, descriptive title
2. Comprehensive description of the incident
3. Appropriate severity level (low, medium, high, critical)
4. Confidence score (0.0 to 1.0)
5. Key entities involved (IPs, users, processes, files)
6. Attack vector identification
7. Specific recommended actions for analysts

Severity Guidelines:
- CRITICAL: Immediate threat to critical assets, active compromise, data exfiltration
- HIGH: Confirmed malicious activity, privilege escalation, lateral movement
- MEDIUM: Suspicious activity requiring investigation, policy violations
- LOW: Anomalous behavior, potential false positive, informational

Consider:
- Business impact and asset criticality
- Attack progression and urgency
- Available context and confidence levels
- Actionability for SOC analysts
- False positive likelihood

Generate alerts that enable quick decision-making and effective response.

Respond in JSON format with the required fields."""
    
    async def process(self, correlation_results: List[CorrelationResult], log_entries: List[NormalizedLogEntry]) -> List[Alert]:
        """Process correlation results and generate final alerts"""
        alerts = []
        
        # Create a mapping of log IDs to log entries
        log_map = {log.id: log for log in log_entries}
        
        for correlation in correlation_results:
            if correlation.correlation_score < 0.3:  # Skip low-confidence correlations
                continue
            
            try:
                log_entry = log_map.get(correlation.log_id)
                if not log_entry:
                    continue
                
                # Create prompt for alert generation
                prompt = self._create_prompt(correlation, log_entry)
                
                # Get LLM response
                response = await self.generate_response(prompt, self.get_system_prompt())
                
                # Parse response and create alert
                alert = self._parse_response(response, correlation, log_entry)
                if alert:
                    alerts.append(alert)
                
            except Exception as e:
                print(f"Error generating alert for correlation {correlation.log_id}: {e}")
                # Create a basic alert for failed processing
                alerts.append(self._create_fallback_alert(correlation, log_entry))
        
        return alerts
    
    def _create_prompt(self, correlation: CorrelationResult, log_entry: NormalizedLogEntry) -> str:
        """Create alert generation prompt"""
        correlation_data = {
            "correlation_score": correlation.correlation_score,
            "related_events": correlation.related_events,
            "context": correlation.context,
            "asset_criticality": correlation.asset_criticality,
            "user_risk_level": correlation.user_risk_level,
            "attack_pattern": correlation.attack_pattern,
            "reasoning": correlation.reasoning,
            "confidence": correlation.confidence
        }
        
        log_data = {
            "id": log_entry.id,
            "source": log_entry.source,
            "timestamp": log_entry.timestamp.isoformat(),
            "event_type": log_entry.event_type,
            "source_ip": log_entry.source_ip,
            "destination_ip": log_entry.destination_ip,
            "user": log_entry.user,
            "process": log_entry.process,
            "command": log_entry.command,
            "file_path": log_entry.file_path,
            "port": log_entry.port,
            "message": log_entry.message,
            "severity": log_entry.severity,
            "tags": log_entry.tags
        }
        
        return f"""Generate a security alert based on this analysis:

CORRELATION ANALYSIS:
{json.dumps(correlation_data, indent=2)}

ORIGINAL LOG ENTRY:
{json.dumps(log_data, indent=2, default=str)}

Create a comprehensive security alert that includes:
1. Clear, actionable title
2. Detailed description of the incident
3. Appropriate severity level
4. Key entities involved
5. Attack vector identification
6. Specific recommended actions

Consider the correlation score, asset criticality, user risk, and business impact when determining severity and recommendations.

Provide the alert in JSON format:
{{
    "title": "Clear, descriptive alert title",
    "description": "Comprehensive incident description",
    "severity": "low|medium|high|critical",
    "confidence": float (0.0-1.0),
    "entities": {{
        "ips": [list of IP addresses],
        "users": [list of users],
        "processes": [list of processes],
        "files": [list of file paths],
        "hosts": [list of hostnames]
    }},
    "attack_vector": "description of attack method",
    "recommended_actions": [
        "Specific action 1",
        "Specific action 2",
        "Specific action 3"
    ]
}}"""
    
    def _parse_response(self, response: str, correlation: CorrelationResult, log_entry: NormalizedLogEntry) -> Alert:
        """Parse LLM response into Alert"""
        try:
            # Clean the response to extract JSON
            response = response.strip()
            if response.startswith('```json'):
                response = response[7:]
            if response.endswith('```'):
                response = response[:-3]
            
            data = json.loads(response)
            
            # Map severity string to enum
            severity_map = {
                'low': SeverityLevel.LOW,
                'medium': SeverityLevel.MEDIUM,
                'high': SeverityLevel.HIGH,
                'critical': SeverityLevel.CRITICAL
            }
            
            severity = severity_map.get(data.get('severity', 'medium').lower(), SeverityLevel.MEDIUM)
            
            # Extract entities
            entities = data.get('entities', {})
            
            # Ensure entities have the expected structure
            normalized_entities = {
                'ips': entities.get('ips', []),
                'users': entities.get('users', []),
                'processes': entities.get('processes', []),
                'files': entities.get('files', []),
                'hosts': entities.get('hosts', [])
            }
            
            # Add entities from log entry if not already included
            if log_entry.source_ip and log_entry.source_ip not in normalized_entities['ips']:
                normalized_entities['ips'].append(log_entry.source_ip)
            if log_entry.destination_ip and log_entry.destination_ip not in normalized_entities['ips']:
                normalized_entities['ips'].append(log_entry.destination_ip)
            if log_entry.user and log_entry.user not in normalized_entities['users']:
                normalized_entities['users'].append(log_entry.user)
            if log_entry.process and log_entry.process not in normalized_entities['processes']:
                normalized_entities['processes'].append(log_entry.process)
            if log_entry.file_path and log_entry.file_path not in normalized_entities['files']:
                normalized_entities['files'].append(log_entry.file_path)
            
            return Alert(
                id=str(uuid.uuid4()),
                title=data.get('title', 'Security Alert'),
                description=data.get('description', 'Security incident detected'),
                severity=severity,
                confidence=max(0.0, min(1.0, data.get('confidence', correlation.confidence))),
                source_log_ids=[correlation.log_id],
                entities=normalized_entities,
                attack_vector=data.get('attack_vector'),
                recommended_actions=data.get('recommended_actions', []),
                status=AlertStatus.NEW,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
        
        except json.JSONDecodeError as e:
            print(f"Failed to parse alert generation response as JSON: {e}")
            print(f"Response: {response}")
            return self._create_fallback_alert(correlation, log_entry, response)
        
        except Exception as e:
            print(f"Error parsing alert generation response: {e}")
            return self._create_fallback_alert(correlation, log_entry)
    
    def _create_fallback_alert(self, correlation: CorrelationResult, log_entry: NormalizedLogEntry, response: str = None) -> Alert:
        """Create a fallback alert when parsing fails"""
        # Determine severity based on correlation score and asset criticality
        if correlation.correlation_score >= 0.8 or correlation.asset_criticality == 'critical':
            severity = SeverityLevel.HIGH
        elif correlation.correlation_score >= 0.6 or correlation.asset_criticality == 'high':
            severity = SeverityLevel.MEDIUM
        else:
            severity = SeverityLevel.LOW
        
        # Extract basic entities
        entities = {
            'ips': [ip for ip in [log_entry.source_ip, log_entry.destination_ip] if ip],
            'users': [log_entry.user] if log_entry.user else [],
            'processes': [log_entry.process] if log_entry.process else [],
            'files': [log_entry.file_path] if log_entry.file_path else [],
            'hosts': []
        }
        
        # Basic recommended actions
        recommended_actions = [
            "Investigate the source IP and user activity",
            "Check for additional related events",
            "Verify if this is legitimate business activity",
            "Consider blocking suspicious IPs if confirmed malicious"
        ]
        
        title = f"Security Alert: {log_entry.event_type.replace('_', ' ').title()}"
        description = f"Suspicious activity detected: {log_entry.message[:200]}..."
        
        if response:
            description += f"\n\nNote: Alert generated from partial analysis: {response[:100]}..."
        
        return Alert(
            id=str(uuid.uuid4()),
            title=title,
            description=description,
            severity=severity,
            confidence=correlation.confidence * 0.7,  # Reduce confidence for fallback
            source_log_ids=[correlation.log_id],
            entities=entities,
            attack_vector=correlation.attack_pattern,
            recommended_actions=recommended_actions,
            status=AlertStatus.NEW,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
