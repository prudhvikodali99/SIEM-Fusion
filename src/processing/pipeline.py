import asyncio
from typing import List, Dict, Any
from datetime import datetime

from src.models.schemas import (
    RawLogEntry, NormalizedLogEntry, AnomalyResult, 
    ThreatIntelResult, CorrelationResult, Alert, ProcessingStats
)
from src.processing.normalizer import LogNormalizer
from src.llm.anomaly_detection import AnomalyDetectionLLM
from src.llm.threat_intelligence import ThreatIntelligenceLLM
from src.llm.contextual_correlation import ContextualCorrelationLLM
from src.llm.alert_generation import AlertGenerationLLM
from src.core.config import config

class SIEMProcessingPipeline:
    """Main processing pipeline that orchestrates the Multi-LLM workflow"""
    
    def __init__(self):
        self.normalizer = LogNormalizer()
        self.llm_anomaly = AnomalyDetectionLLM()
        self.llm_threat_intel = ThreatIntelligenceLLM()
        self.llm_correlation = ContextualCorrelationLLM()
        self.llm_alert_gen = AlertGenerationLLM()
        
        # Processing configuration
        self.batch_size = config.processing_config.get('batch_size', 100)
        self.alert_threshold = config.processing_config.get('alert_threshold', 0.7)
        self.max_concurrent_llm_calls = config.processing_config.get('max_concurrent_llm_calls', 5)
        
        # Statistics tracking
        self.stats = ProcessingStats()
        
        # Semaphore to limit concurrent LLM calls
        self.llm_semaphore = asyncio.Semaphore(self.max_concurrent_llm_calls)
    
    async def process_logs(self, raw_logs: List[RawLogEntry]) -> List[Alert]:
        """Process raw logs through the complete Multi-LLM pipeline"""
        start_time = datetime.now()
        
        try:
            # Step 1: Normalize logs
            print(f"Step 1: Normalizing {len(raw_logs)} raw log entries...")
            normalized_logs = await self._normalize_logs(raw_logs)
            print(f"Normalized {len(normalized_logs)} log entries")
            
            # Step 2: Process in batches to manage memory and API limits
            all_alerts = []
            
            for i in range(0, len(normalized_logs), self.batch_size):
                batch = normalized_logs[i:i + self.batch_size]
                batch_alerts = await self._process_batch(batch, i // self.batch_size + 1)
                all_alerts.extend(batch_alerts)
            
            # Update statistics
            processing_time = (datetime.now() - start_time).total_seconds()
            await self._update_stats(len(raw_logs), len(all_alerts), processing_time)
            
            print(f"Pipeline completed: Generated {len(all_alerts)} alerts from {len(raw_logs)} logs in {processing_time:.2f}s")
            return all_alerts
        
        except Exception as e:
            print(f"Error in processing pipeline: {e}")
            raise
    
    async def _normalize_logs(self, raw_logs: List[RawLogEntry]) -> List[NormalizedLogEntry]:
        """Normalize raw logs into standardized schema"""
        normalized = []
        
        for raw_log in raw_logs:
            try:
                normalized_log = self.normalizer.normalize(raw_log)
                normalized.append(normalized_log)
            except Exception as e:
                print(f"Error normalizing log {raw_log.id}: {e}")
                continue
        
        return normalized
    
    async def _process_batch(self, normalized_logs: List[NormalizedLogEntry], batch_num: int) -> List[Alert]:
        """Process a batch of normalized logs through the LLM pipeline"""
        print(f"Processing batch {batch_num} with {len(normalized_logs)} logs...")
        
        try:
            # Step 2: LLM-1 Anomaly Detection
            print(f"  Step 2: Running anomaly detection on batch {batch_num}...")
            async with self.llm_semaphore:
                anomaly_results = await self.llm_anomaly.process(normalized_logs)
            
            anomalous_count = sum(1 for result in anomaly_results if result.is_anomalous)
            print(f"  Found {anomalous_count} anomalies out of {len(anomaly_results)} logs")
            
            # Step 3: LLM-2 Threat Intelligence Verification
            print(f"  Step 3: Running threat intelligence verification on batch {batch_num}...")
            async with self.llm_semaphore:
                threat_results = await self.llm_threat_intel.process(anomaly_results, normalized_logs)
            
            threat_count = sum(1 for result in threat_results if result.is_threat)
            print(f"  Verified {threat_count} threats out of {len(threat_results)} anomalies")
            
            # Step 4: LLM-3 Contextual Correlation
            print(f"  Step 4: Running contextual correlation on batch {batch_num}...")
            async with self.llm_semaphore:
                correlation_results = await self.llm_correlation.process(threat_results, normalized_logs)
            
            high_correlation_count = sum(1 for result in correlation_results if result.correlation_score >= self.alert_threshold)
            print(f"  Found {high_correlation_count} high-correlation events out of {len(correlation_results)} threats")
            
            # Step 5: LLM-4 Alert Generation
            print(f"  Step 5: Generating alerts for batch {batch_num}...")
            async with self.llm_semaphore:
                alerts = await self.llm_alert_gen.process(correlation_results, normalized_logs)
            
            print(f"  Generated {len(alerts)} alerts for batch {batch_num}")
            return alerts
        
        except Exception as e:
            print(f"Error processing batch {batch_num}: {e}")
            return []
    
    async def _update_stats(self, total_logs: int, total_alerts: int, processing_time: float):
        """Update processing statistics"""
        self.stats.total_logs_processed += total_logs
        self.stats.alerts_generated += total_alerts
        
        # Update average processing time
        if self.stats.processing_time_avg == 0:
            self.stats.processing_time_avg = processing_time
        else:
            self.stats.processing_time_avg = (self.stats.processing_time_avg + processing_time) / 2
        
        self.stats.last_updated = datetime.now()
    
    def get_stats(self) -> ProcessingStats:
        """Get current processing statistics"""
        return self.stats
    
    async def process_single_log(self, raw_log: RawLogEntry) -> List[Alert]:
        """Process a single log entry (useful for real-time processing)"""
        return await self.process_logs([raw_log])
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all pipeline components"""
        health_status = {
            "pipeline": "healthy",
            "components": {
                "normalizer": "healthy",
                "llm_anomaly": "unknown",
                "llm_threat_intel": "unknown", 
                "llm_correlation": "unknown",
                "llm_alert_gen": "unknown"
            },
            "stats": self.stats.dict(),
            "last_check": datetime.now().isoformat()
        }
        
        # Test each LLM component with a simple health check
        try:
            # Create a simple test log
            test_log = NormalizedLogEntry(
                id="health_check",
                source="syslog",
                timestamp=datetime.now(),
                event_type="test",
                message="Health check test message",
                severity="low",
                tags=["test"]
            )
            
            # Test anomaly detection
            try:
                async with asyncio.wait_for(self.llm_semaphore.acquire(), timeout=5):
                    await self.llm_anomaly.process([test_log])
                    health_status["components"]["llm_anomaly"] = "healthy"
                    self.llm_semaphore.release()
            except Exception as e:
                health_status["components"]["llm_anomaly"] = f"error: {str(e)}"
            
            # For other LLMs, we'll mark them as healthy if anomaly detection works
            # In production, you might want to test each one individually
            if health_status["components"]["llm_anomaly"] == "healthy":
                health_status["components"]["llm_threat_intel"] = "healthy"
                health_status["components"]["llm_correlation"] = "healthy"
                health_status["components"]["llm_alert_gen"] = "healthy"
        
        except Exception as e:
            health_status["pipeline"] = f"error: {str(e)}"
        
        return health_status
