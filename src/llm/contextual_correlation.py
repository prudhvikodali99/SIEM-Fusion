import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
from src.llm.base import BaseLLM
from src.models.schemas import NormalizedLogEntry, ThreatIntelResult, CorrelationResult

class ContextualCorrelationLLM(BaseLLM):
    """LLM-3: Contextual Correlation - Adds context by correlating events across the network"""
    
    def __init__(self):
        super().__init__('contextual_correlation')
        # Mock asset and user databases for demo
        self.asset_database = self._load_asset_database()
        self.user_database = self._load_user_database()
        self.historical_events = []  # In production, this would be a proper database
    
    def get_system_prompt(self) -> str:
        return """You are an expert security analyst specializing in event correlation and contextual analysis.

Your role is to enrich verified threats with contextual information by:

1. Correlating events across time and systems
2. Analyzing user behavior patterns
3. Assessing asset criticality and business impact
4. Identifying attack chains and kill chains
5. Mapping to MITRE ATT&CK framework
6. Evaluating lateral movement patterns
7. Considering business context and risk

For each verified threat, provide:
- Related events and correlations
- Correlation score (0.0 to 1.0)
- Contextual information (asset criticality, user risk, etc.)
- Attack pattern identification
- Business impact assessment
- Clear reasoning for correlations
- Confidence level (0.0 to 1.0)

Consider:
- Temporal relationships between events
- Geographical and network topology
- User roles and access patterns
- Asset importance and criticality
- Historical attack patterns
- Business processes and workflows

Respond in JSON format with the required fields."""
    
    def _load_asset_database(self) -> Dict[str, Dict[str, Any]]:
        """Load asset criticality database (mock data)"""
        return {
            "192.168.1.10": {"type": "domain_controller", "criticality": "critical", "department": "IT"},
            "192.168.1.20": {"type": "file_server", "criticality": "high", "department": "Finance"},
            "192.168.1.30": {"type": "web_server", "criticality": "high", "department": "Marketing"},
            "192.168.1.100": {"type": "workstation", "criticality": "medium", "department": "HR"},
            "192.168.1.200": {"type": "database_server", "criticality": "critical", "department": "Finance"},
            "10.0.0.50": {"type": "backup_server", "criticality": "high", "department": "IT"}
        }
    
    def _load_user_database(self) -> Dict[str, Dict[str, Any]]:
        """Load user risk database (mock data)"""
        return {
            "admin": {"role": "administrator", "risk_level": "high", "department": "IT", "privileged": True},
            "jdoe": {"role": "analyst", "risk_level": "medium", "department": "Finance", "privileged": False},
            "msmith": {"role": "manager", "risk_level": "medium", "department": "HR", "privileged": False},
            "service_account": {"role": "service", "risk_level": "low", "department": "IT", "privileged": True},
            "guest": {"role": "guest", "risk_level": "high", "department": "Unknown", "privileged": False}
        }
    
    async def process(self, threat_results: List[ThreatIntelResult], log_entries: List[NormalizedLogEntry]) -> List[CorrelationResult]:
        """Process verified threats and add contextual correlation"""
        results = []
        
        # Create a mapping of log IDs to log entries
        log_map = {log.id: log for log in log_entries}
        
        # Add current log entries to historical events for correlation
        self.historical_events.extend(log_entries)
        
        # Keep only recent events (last 24 hours for demo)
        cutoff_time = datetime.now() - timedelta(hours=24)
        self.historical_events = [
            event for event in self.historical_events 
            if event.timestamp > cutoff_time
        ]
        
        for threat in threat_results:
            if not threat.is_threat:
                # Skip non-threats
                results.append(CorrelationResult(
                    log_id=threat.log_id,
                    correlation_score=0.0,
                    reasoning="Not identified as a threat",
                    confidence=1.0
                ))
                continue
            
            try:
                log_entry = log_map.get(threat.log_id)
                if not log_entry:
                    continue
                
                # Create prompt for contextual correlation
                prompt = self._create_prompt(threat, log_entry)
                
                # Get LLM response
                response = await self.generate_response(prompt, self.get_system_prompt())
                
                # Parse response and create result
                result = self._parse_response(response, threat.log_id)
                results.append(result)
                
            except Exception as e:
                print(f"Error processing threat {threat.log_id} for contextual correlation: {e}")
                results.append(CorrelationResult(
                    log_id=threat.log_id,
                    correlation_score=0.0,
                    reasoning=f"Processing failed: {str(e)}",
                    confidence=0.0
                ))
        
        return results
    
    def _create_prompt(self, threat: ThreatIntelResult, log_entry: NormalizedLogEntry) -> str:
        """Create contextual correlation prompt"""
        # Get asset and user context
        asset_context = self._get_asset_context(log_entry)
        user_context = self._get_user_context(log_entry)
        
        # Find related events
        related_events = self._find_related_events(log_entry)
        
        threat_data = {
            "threat_type": threat.threat_type,
            "threat_score": threat.threat_score,
            "ioc_matches": threat.ioc_matches,
            "reasoning": threat.reasoning,
            "confidence": threat.confidence
        }
        
        log_data = {
            "id": log_entry.id,
            "timestamp": log_entry.timestamp.isoformat(),
            "event_type": log_entry.event_type,
            "source_ip": log_entry.source_ip,
            "destination_ip": log_entry.destination_ip,
            "user": log_entry.user,
            "process": log_entry.process,
            "command": log_entry.command,
            "message": log_entry.message,
            "tags": log_entry.tags
        }
        
        return f"""Perform contextual correlation analysis for this verified threat:

THREAT DETAILS:
{json.dumps(threat_data, indent=2)}

LOG ENTRY:
{json.dumps(log_data, indent=2, default=str)}

ASSET CONTEXT:
{json.dumps(asset_context, indent=2)}

USER CONTEXT:
{json.dumps(user_context, indent=2)}

RELATED EVENTS (last 24h):
{json.dumps(related_events, indent=2, default=str)}

Analyze and correlate this threat with:
1. Related events in the time window
2. Asset criticality and business impact
3. User behavior and risk patterns
4. Attack chain progression
5. Lateral movement indicators
6. Business process context

Provide correlation analysis in JSON format:
{{
    "related_events": [list of related event IDs],
    "correlation_score": float (0.0-1.0),
    "context": {{
        "asset_criticality": string,
        "user_risk_level": string,
        "business_impact": string,
        "attack_stage": string,
        "lateral_movement": boolean,
        "privilege_escalation": boolean
    }},
    "attack_pattern": string or null,
    "reasoning": "detailed correlation analysis",
    "confidence": float (0.0-1.0)
}}"""
    
    def _get_asset_context(self, log_entry: NormalizedLogEntry) -> Dict[str, Any]:
        """Get asset context for IPs in the log entry"""
        context = {}
        
        if log_entry.source_ip:
            asset_info = self.asset_database.get(log_entry.source_ip, {})
            if asset_info:
                context["source_asset"] = asset_info
        
        if log_entry.destination_ip:
            asset_info = self.asset_database.get(log_entry.destination_ip, {})
            if asset_info:
                context["destination_asset"] = asset_info
        
        return context
    
    def _get_user_context(self, log_entry: NormalizedLogEntry) -> Dict[str, Any]:
        """Get user context for the log entry"""
        if not log_entry.user:
            return {}
        
        user_info = self.user_database.get(log_entry.user, {})
        return {"user_profile": user_info} if user_info else {}
    
    def _find_related_events(self, log_entry: NormalizedLogEntry, time_window_hours: int = 2) -> List[Dict[str, Any]]:
        """Find events related to this log entry within a time window"""
        related = []
        cutoff_time = log_entry.timestamp - timedelta(hours=time_window_hours)
        
        for event in self.historical_events:
            if event.id == log_entry.id:
                continue
            
            if event.timestamp < cutoff_time:
                continue
            
            # Check for relationships
            is_related = False
            relationship_type = None
            
            # Same user
            if log_entry.user and event.user == log_entry.user:
                is_related = True
                relationship_type = "same_user"
            
            # Same source IP
            elif log_entry.source_ip and event.source_ip == log_entry.source_ip:
                is_related = True
                relationship_type = "same_source_ip"
            
            # IP correlation (source -> destination)
            elif (log_entry.source_ip and event.destination_ip == log_entry.source_ip) or \
                 (log_entry.destination_ip and event.source_ip == log_entry.destination_ip):
                is_related = True
                relationship_type = "ip_correlation"
            
            # Same process
            elif log_entry.process and event.process == log_entry.process:
                is_related = True
                relationship_type = "same_process"
            
            if is_related:
                related.append({
                    "id": event.id,
                    "timestamp": event.timestamp.isoformat(),
                    "event_type": event.event_type,
                    "relationship": relationship_type,
                    "message": event.message[:100] + "..." if len(event.message) > 100 else event.message
                })
        
        # Limit to most recent 10 related events
        return sorted(related, key=lambda x: x["timestamp"], reverse=True)[:10]
    
    def _parse_response(self, response: str, log_id: str) -> CorrelationResult:
        """Parse LLM response into CorrelationResult"""
        try:
            # Clean the response to extract JSON
            response = response.strip()
            if response.startswith('```json'):
                response = response[7:]
            if response.endswith('```'):
                response = response[:-3]
            
            data = json.loads(response)
            
            # Extract context with defaults
            context = data.get('context', {})
            
            return CorrelationResult(
                log_id=log_id,
                related_events=data.get('related_events', []),
                correlation_score=max(0.0, min(1.0, data.get('correlation_score', 0.0))),
                context=context,
                asset_criticality=context.get('asset_criticality', 'unknown'),
                user_risk_level=context.get('user_risk_level', 'unknown'),
                attack_pattern=data.get('attack_pattern'),
                reasoning=data.get('reasoning', 'No reasoning provided'),
                confidence=max(0.0, min(1.0, data.get('confidence', 0.0))),
                timestamp=datetime.now()
            )
        
        except json.JSONDecodeError as e:
            print(f"Failed to parse correlation response as JSON: {e}")
            print(f"Response: {response}")
            
            return CorrelationResult(
                log_id=log_id,
                correlation_score=0.3,
                reasoning=f"Parsed from text response: {response[:200]}...",
                confidence=0.2,
                timestamp=datetime.now()
            )
        
        except Exception as e:
            print(f"Error parsing correlation response: {e}")
            return CorrelationResult(
                log_id=log_id,
                correlation_score=0.0,
                reasoning=f"Error parsing response: {str(e)}",
                confidence=0.0,
                timestamp=datetime.now()
            )
