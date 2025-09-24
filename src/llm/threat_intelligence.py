import json
from datetime import datetime
from typing import List
from src.llm.base import BaseLLM
from src.models.schemas import NormalizedLogEntry, AnomalyResult, ThreatIntelResult

class ThreatIntelligenceLLM(BaseLLM):
    """LLM-2: Threat Intelligence Verification - Cross-references anomalies with threat intelligence"""
    
    def __init__(self):
        super().__init__('threat_intelligence')
        # In a real implementation, this would connect to threat intel feeds
        self.threat_indicators = self._load_threat_indicators()
    
    def get_system_prompt(self) -> str:
        return """You are an expert threat intelligence analyst for a SIEM system.

Your role is to verify anomalies against known threat intelligence, including:

1. Known malicious IP addresses and domains
2. Indicators of Compromise (IoCs)
3. Malware signatures and behaviors
4. Attack patterns and TTPs (Tactics, Techniques, Procedures)
5. CVE databases and vulnerability information
6. Threat actor profiles and campaigns

For each anomaly, determine:
- Whether it matches known threat intelligence (true/false)
- Type of threat if identified
- Specific IoC matches
- Threat score (0.0 to 1.0, where 1.0 is highest threat)
- Clear reasoning for your assessment
- Confidence level (0.0 to 1.0)

Consider:
- IP reputation databases
- Known malware families
- Attack frameworks (MITRE ATT&CK)
- Recent threat campaigns
- False positive patterns

Respond in JSON format with the required fields."""
    
    def _load_threat_indicators(self) -> dict:
        """Load threat intelligence indicators (mock data for demo)"""
        return {
            "malicious_ips": [
                "192.168.1.100", "10.0.0.50", "172.16.1.200",
                "185.220.100.240", "198.51.100.1"
            ],
            "suspicious_processes": [
                "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                "regsvr32.exe", "rundll32.exe", "certutil.exe"
            ],
            "malware_signatures": [
                "mimikatz", "cobalt strike", "metasploit", "empire",
                "bloodhound", "sharphound", "rubeus"
            ],
            "attack_patterns": {
                "lateral_movement": ["psexec", "wmi", "rdp", "ssh"],
                "privilege_escalation": ["uac bypass", "token impersonation"],
                "persistence": ["scheduled task", "registry run key", "service"],
                "exfiltration": ["ftp", "http post", "dns tunneling"]
            },
            "suspicious_ports": [4444, 8080, 1337, 31337, 6666],
            "file_extensions": [".exe", ".scr", ".bat", ".ps1", ".vbs"]
        }
    
    async def process(self, anomaly_results: List[AnomalyResult], log_entries: List[NormalizedLogEntry]) -> List[ThreatIntelResult]:
        """Process anomalies and verify against threat intelligence"""
        results = []
        
        # Create a mapping of log IDs to log entries for quick lookup
        log_map = {log.id: log for log in log_entries}
        
        for anomaly in anomaly_results:
            if not anomaly.is_anomalous:
                # Skip non-anomalous entries
                results.append(ThreatIntelResult(
                    log_id=anomaly.log_id,
                    is_threat=False,
                    threat_score=0.0,
                    reasoning="Not flagged as anomalous",
                    confidence=1.0
                ))
                continue
            
            try:
                log_entry = log_map.get(anomaly.log_id)
                if not log_entry:
                    continue
                
                # Create prompt for threat intelligence verification
                prompt = self._create_prompt(anomaly, log_entry)
                
                # Get LLM response
                response = await self.generate_response(prompt, self.get_system_prompt())
                
                # Parse response and create result
                result = self._parse_response(response, anomaly.log_id)
                results.append(result)
                
            except Exception as e:
                print(f"Error processing anomaly {anomaly.log_id} for threat intelligence: {e}")
                results.append(ThreatIntelResult(
                    log_id=anomaly.log_id,
                    is_threat=False,
                    threat_score=0.0,
                    reasoning=f"Processing failed: {str(e)}",
                    confidence=0.0
                ))
        
        return results
    
    def _create_prompt(self, anomaly: AnomalyResult, log_entry: NormalizedLogEntry) -> str:
        """Create threat intelligence verification prompt"""
        # Include relevant threat intelligence context
        threat_context = self._get_relevant_threat_context(log_entry)
        
        anomaly_data = {
            "anomaly_score": anomaly.anomaly_score,
            "anomaly_type": anomaly.anomaly_type,
            "reasoning": anomaly.reasoning,
            "confidence": anomaly.confidence
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
            "tags": log_entry.tags
        }
        
        return f"""Verify this anomaly against threat intelligence:

ANOMALY DETAILS:
{json.dumps(anomaly_data, indent=2)}

LOG ENTRY:
{json.dumps(log_data, indent=2, default=str)}

THREAT INTELLIGENCE CONTEXT:
{json.dumps(threat_context, indent=2)}

Analyze whether this anomaly matches known threat intelligence:
1. Check IPs against reputation databases
2. Verify processes against known malware
3. Match patterns against attack frameworks
4. Consider recent threat campaigns
5. Evaluate IoC matches

Provide your assessment in JSON format:
{{
    "is_threat": boolean,
    "threat_type": string or null,
    "ioc_matches": [list of matched indicators],
    "threat_score": float (0.0-1.0),
    "reasoning": "detailed explanation",
    "confidence": float (0.0-1.0)
}}"""
    
    def _get_relevant_threat_context(self, log_entry: NormalizedLogEntry) -> dict:
        """Get relevant threat intelligence context for the log entry"""
        context = {}
        
        # Check IP addresses
        if log_entry.source_ip:
            context["source_ip_reputation"] = log_entry.source_ip in self.threat_indicators["malicious_ips"]
        
        if log_entry.destination_ip:
            context["dest_ip_reputation"] = log_entry.destination_ip in self.threat_indicators["malicious_ips"]
        
        # Check processes
        if log_entry.process:
            process_name = log_entry.process.lower()
            context["suspicious_process"] = any(
                susp_proc in process_name for susp_proc in self.threat_indicators["suspicious_processes"]
            )
        
        # Check for malware signatures in message
        if log_entry.message:
            message_lower = log_entry.message.lower()
            context["malware_signatures"] = [
                sig for sig in self.threat_indicators["malware_signatures"]
                if sig in message_lower
            ]
        
        # Check ports
        if log_entry.port:
            context["suspicious_port"] = log_entry.port in self.threat_indicators["suspicious_ports"]
        
        # Check attack patterns
        message_lower = log_entry.message.lower() if log_entry.message else ""
        for pattern_type, keywords in self.threat_indicators["attack_patterns"].items():
            if any(keyword in message_lower for keyword in keywords):
                context[f"attack_pattern_{pattern_type}"] = True
        
        return context
    
    def _parse_response(self, response: str, log_id: str) -> ThreatIntelResult:
        """Parse LLM response into ThreatIntelResult"""
        try:
            # Clean the response to extract JSON
            response = response.strip()
            if response.startswith('```json'):
                response = response[7:]
            if response.endswith('```'):
                response = response[:-3]
            
            data = json.loads(response)
            
            return ThreatIntelResult(
                log_id=log_id,
                is_threat=data.get('is_threat', False),
                threat_type=data.get('threat_type'),
                ioc_matches=data.get('ioc_matches', []),
                threat_score=max(0.0, min(1.0, data.get('threat_score', 0.0))),
                reasoning=data.get('reasoning', 'No reasoning provided'),
                confidence=max(0.0, min(1.0, data.get('confidence', 0.0))),
                timestamp=datetime.now()
            )
        
        except json.JSONDecodeError as e:
            print(f"Failed to parse threat intelligence response as JSON: {e}")
            print(f"Response: {response}")
            
            # Fallback: try to extract information from text
            is_threat = 'true' in response.lower() and 'threat' in response.lower()
            
            return ThreatIntelResult(
                log_id=log_id,
                is_threat=is_threat,
                threat_score=0.7 if is_threat else 0.1,
                reasoning=f"Parsed from text response: {response[:200]}...",
                confidence=0.3,
                timestamp=datetime.now()
            )
        
        except Exception as e:
            print(f"Error parsing threat intelligence response: {e}")
            return ThreatIntelResult(
                log_id=log_id,
                is_threat=False,
                threat_score=0.0,
                reasoning=f"Error parsing response: {str(e)}",
                confidence=0.0,
                timestamp=datetime.now()
            )
