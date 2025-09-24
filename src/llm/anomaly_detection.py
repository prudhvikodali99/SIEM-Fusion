import json
from datetime import datetime
from typing import List
from src.llm.base import BaseLLM
from src.models.schemas import NormalizedLogEntry, AnomalyResult

class AnomalyDetectionLLM(BaseLLM):
    """LLM-1: Anomaly Detection - Identifies patterns and outliers in log data"""
    
    def __init__(self):
        super().__init__('anomaly_detection')
    
    def get_system_prompt(self) -> str:
        return """You are an expert cybersecurity analyst specializing in anomaly detection for SIEM systems.

Your role is to analyze normalized log entries and identify potential anomalies that deviate from normal patterns. You should look for:

1. Unusual patterns in user behavior
2. Abnormal network connections
3. Suspicious process executions
4. Irregular file system activities
5. Authentication anomalies
6. Time-based irregularities
7. Volume-based anomalies

For each log entry, determine:
- Whether it represents an anomaly (true/false)
- Anomaly score (0.0 to 1.0, where 1.0 is most anomalous)
- Type of anomaly if detected
- Clear reasoning for your decision
- Confidence level (0.0 to 1.0)

Focus on behavioral deviations, statistical outliers, and patterns that could indicate security threats.
Be precise but not overly sensitive to avoid false positives.

Respond in JSON format with the required fields."""
    
    async def process(self, log_entries: List[NormalizedLogEntry]) -> List[AnomalyResult]:
        """Process log entries and detect anomalies"""
        results = []
        
        for log_entry in log_entries:
            try:
                # Create prompt for this log entry
                prompt = self._create_prompt(log_entry)
                
                # Get LLM response
                response = await self.generate_response(prompt, self.get_system_prompt())
                
                # Parse response and create result
                result = self._parse_response(response, log_entry.id)
                results.append(result)
                
            except Exception as e:
                print(f"Error processing log {log_entry.id} for anomaly detection: {e}")
                # Create a default result for failed processing
                results.append(AnomalyResult(
                    log_id=log_entry.id,
                    is_anomalous=False,
                    anomaly_score=0.0,
                    reasoning=f"Processing failed: {str(e)}",
                    confidence=0.0
                ))
        
        return results
    
    def _create_prompt(self, log_entry: NormalizedLogEntry) -> str:
        """Create analysis prompt for a log entry"""
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
            "protocol": log_entry.protocol,
            "status_code": log_entry.status_code,
            "message": log_entry.message,
            "severity": log_entry.severity,
            "tags": log_entry.tags,
            "log_metadata": log_entry.log_metadata
        }
        
        return f"""Analyze this log entry for anomalies:

{json.dumps(log_data, indent=2, default=str)}

Consider the following factors:
1. Is this behavior typical for the user/system?
2. Are there unusual patterns in timing, location, or access?
3. Does the activity suggest potential security concerns?
4. Are there statistical outliers in the data?
5. Does this match known attack patterns?

Provide your analysis in the following JSON format:
{{
    "is_anomalous": boolean,
    "anomaly_score": float (0.0-1.0),
    "anomaly_type": string or null,
    "reasoning": "detailed explanation",
    "confidence": float (0.0-1.0)
}}"""
    
    def _parse_response(self, response: str, log_id: str) -> AnomalyResult:
        """Parse LLM response into AnomalyResult"""
        try:
            # Clean the response to extract JSON
            response = response.strip()
            if response.startswith('```json'):
                response = response[7:]
            if response.endswith('```'):
                response = response[:-3]
            
            data = json.loads(response)
            
            return AnomalyResult(
                log_id=log_id,
                is_anomalous=data.get('is_anomalous', False),
                anomaly_score=max(0.0, min(1.0, data.get('anomaly_score', 0.0))),
                anomaly_type=data.get('anomaly_type'),
                reasoning=data.get('reasoning', 'No reasoning provided'),
                confidence=max(0.0, min(1.0, data.get('confidence', 0.0))),
                timestamp=datetime.now()
            )
        
        except json.JSONDecodeError as e:
            print(f"Failed to parse LLM response as JSON: {e}")
            print(f"Response: {response}")
            
            # Fallback: try to extract information from text
            is_anomalous = 'true' in response.lower() and 'anomalous' in response.lower()
            
            return AnomalyResult(
                log_id=log_id,
                is_anomalous=is_anomalous,
                anomaly_score=0.5 if is_anomalous else 0.1,
                reasoning=f"Parsed from text response: {response[:200]}...",
                confidence=0.3,
                timestamp=datetime.now()
            )
        
        except Exception as e:
            print(f"Error parsing anomaly detection response: {e}")
            return AnomalyResult(
                log_id=log_id,
                is_anomalous=False,
                anomaly_score=0.0,
                reasoning=f"Error parsing response: {str(e)}",
                confidence=0.0,
                timestamp=datetime.now()
            )
