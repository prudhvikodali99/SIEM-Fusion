import asyncio
import threading
import time
from datetime import datetime
from typing import List

from src.collectors.manager import CollectorManager
from src.processing.pipeline import SIEMProcessingPipeline
from src.dashboard.beautiful_app import BeautifulSIEMDashboard
from src.models.schemas import RawLogEntry, Alert
from src.core.config import config

class SIEMFusionApp:
    """Main SIEM-Fusion application that orchestrates all components"""
    
    def __init__(self):
        # Initialize collector manager with dataset support
        self.collector_manager = CollectorManager(use_datasets=True)
        self.processing_pipeline = SIEMProcessingPipeline()
        self.dashboard = BeautifulSIEMDashboard()
        
        self.running = False
        self.processing_interval = config.processing_config.get('processing_interval', 30)
        
        # Storage for collected logs (in production, this would be a proper queue/database)
        self.log_buffer: List[RawLogEntry] = []
        self.buffer_lock = asyncio.Lock()
    
    async def start(self):
        """Start the SIEM-Fusion application"""
        print("🚀 Starting SIEM-Fusion Multi-LLM Integration System...")
        
        try:
            # Start data collectors
            print("📡 Starting data collectors...")
            await self.collector_manager.start_collection()
            
            # Start the main processing loop
            self.running = True
            print("⚙️  Starting processing pipeline...")
            
            # Start dashboard in a separate thread
            dashboard_thread = threading.Thread(
                target=self._start_dashboard,
                daemon=True
            )
            dashboard_thread.start()
            
            # Start log collection and processing tasks
            await asyncio.gather(
                self._log_collection_loop(),
                self._processing_loop(),
                return_exceptions=True
            )
        
        except KeyboardInterrupt:
            print("\n🛑 Shutting down SIEM-Fusion...")
            await self.stop()
        except Exception as e:
            print(f"❌ Error starting SIEM-Fusion: {e}")
            await self.stop()
    
    async def stop(self):
        """Stop the SIEM-Fusion application"""
        self.running = False
        
        print("🔄 Stopping data collectors...")
        await self.collector_manager.stop_collection()
        
        print("✅ SIEM-Fusion stopped successfully")
    
    def _start_dashboard(self):
        """Start the dashboard in a separate thread"""
        try:
            print("🌐 Starting SOC Dashboard...")
            dashboard_host = config.dashboard_config.get('host', '0.0.0.0')
            dashboard_port = config.dashboard_config.get('port', 8080)
            print(f"📊 Dashboard available at: http://{dashboard_host}:{dashboard_port}")
            
            self.dashboard.run(debug=False)
        except Exception as e:
            print(f"❌ Error starting dashboard: {e}")
    
    async def _log_collection_loop(self):
        """Continuously collect logs from all sources"""
        print("🔍 Starting log collection loop...")
        
        try:
            while self.running:
                # Get the async generator
                log_generator = self.collector_manager.collect_all_logs()
                
                # Iterate through the logs
                async for log_entry in log_generator:
                    if not self.running:
                        break
                        
                    async with self.buffer_lock:
                        self.log_buffer.append(log_entry)
                        
                        # Prevent buffer from growing too large
                        if len(self.log_buffer) > 1000:
                            self.log_buffer = self.log_buffer[-500:]  # Keep most recent 500
                    
                    print(f"📥 Collected log: {log_entry.id} from {log_entry.source}")
                
                # Small delay before restarting collection
                await asyncio.sleep(1)
        
        except Exception as e:
            print(f"❌ Error in log collection loop: {e}")
    
    async def _processing_loop(self):
        """Periodically process collected logs through the LLM pipeline"""
        print(f"🔄 Starting processing loop (interval: {self.processing_interval}s)...")
        
        while self.running:
            try:
                # Get logs from buffer
                async with self.buffer_lock:
                    if not self.log_buffer:
                        await asyncio.sleep(self.processing_interval)
                        continue
                    
                    # Process logs in batches
                    logs_to_process = self.log_buffer.copy()
                    self.log_buffer.clear()
                
                if logs_to_process:
                    print(f"🧠 Processing {len(logs_to_process)} logs through LLM pipeline...")
                    
                    # Process logs through the Multi-LLM pipeline
                    alerts = await self.processing_pipeline.process_logs(logs_to_process)
                    
                    # Add alerts to dashboard
                    for alert in alerts:
                        self.dashboard.add_alert(alert)
                        print(f"🚨 Generated alert: {alert.title} (Severity: {alert.severity.value})")
                    
                    # Update dashboard statistics
                    stats = self.processing_pipeline.get_stats()
                    self.dashboard.update_stats(stats)
                    
                    print(f"✅ Processing complete: {len(alerts)} alerts generated")
                
                # Wait before next processing cycle
                await asyncio.sleep(self.processing_interval)
            
            except Exception as e:
                print(f"❌ Error in processing loop: {e}")
                await asyncio.sleep(5)  # Wait before retrying
    
    async def health_check(self):
        """Perform comprehensive health check"""
        print("🏥 Performing system health check...")
        
        health_status = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": "healthy",
            "components": {}
        }
        
        try:
            # Check collectors
            collector_status = self.collector_manager.get_collector_status()
            health_status["components"]["collectors"] = collector_status
            
            # Check processing pipeline
            pipeline_health = await self.processing_pipeline.health_check()
            health_status["components"]["pipeline"] = pipeline_health
            
            # Check dashboard (basic check)
            health_status["components"]["dashboard"] = {
                "status": "healthy" if hasattr(self.dashboard, 'app') else "error",
                "alerts_count": len(self.dashboard.alerts)
            }
            
            # Determine overall status
            component_statuses = []
            for component, status in health_status["components"].items():
                if isinstance(status, dict):
                    if "status" in status:
                        component_statuses.append(status["status"])
                    else:
                        # For collectors, check if any are healthy
                        healthy_collectors = any(
                            collector.get("healthy", False) 
                            for collector in status.values()
                        )
                        component_statuses.append("healthy" if healthy_collectors else "error")
            
            if any("error" in str(status) for status in component_statuses):
                health_status["overall_status"] = "degraded"
            
            print("✅ Health check completed")
            return health_status
        
        except Exception as e:
            print(f"❌ Health check failed: {e}")
            health_status["overall_status"] = "error"
            health_status["error"] = str(e)
            return health_status

async def main():
    """Main entry point"""
    print("=" * 60)
    print("🛡️  SIEM-FUSION: Multi-LLM Integration for SIEM")
    print("   Advanced Threat Detection & Analysis System")
    print("=" * 60)
    
    # Create and start the application
    app = SIEMFusionApp()
    
    try:
        await app.start()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"💥 Fatal error: {e}")

if __name__ == "__main__":
    # Check if required environment variables are set
    import os
    
    required_env_vars = ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY']
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    
    if missing_vars:
        print("⚠️  Warning: Missing required environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\nPlease set these environment variables before running the application.")
        print("Example:")
        print("   export OPENAI_API_KEY='your-openai-api-key'")
        print("   export ANTHROPIC_API_KEY='your-anthropic-api-key'")
        exit(1)
    
    # Run the application
    asyncio.run(main())
