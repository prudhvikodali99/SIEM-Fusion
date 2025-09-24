"""
Dataset Loader for SIEM-Fusion
Loads and processes security datasets from CSV files
"""

import pandas as pd
import os
import json
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Generator
from pathlib import Path
import asyncio
import logging

from src.database.models import LogEntry
from src.core.config import config

class DatasetLoader:
    """Loads security datasets from CSV files and converts to LogEntry format"""
    
    def __init__(self, datasets_path: str = "datasets"):
        self.datasets_path = Path(datasets_path)
        self.logger = logging.getLogger(__name__)
        
        # Dataset type mappings
        self.dataset_configs = {
            "network_intrusion": {
                "cicids2017": self._process_cicids2017,
                "unsw_nb15": self._process_unsw_nb15,
                "nsl_kdd": self._process_nsl_kdd
            },
            "windows_events": {
                "security_logs": self._process_windows_security,
                "system_logs": self._process_windows_system
            },
            "malware": {
                "android": self._process_android_malware,
                "samples": self._process_malware_samples
            },
            "syslog": {
                "firewall": self._process_firewall_logs,
                "router": self._process_router_logs,
                "server": self._process_server_logs
            }
        }
    
    async def load_all_datasets(self) -> Generator[LogEntry, None, None]:
        """Load all available datasets and yield LogEntry objects"""
        self.logger.info("🔄 Starting dataset loading...")
        
        total_entries = 0
        for category, subcategories in self.dataset_configs.items():
            category_path = self.datasets_path / category
            
            if not category_path.exists():
                self.logger.warning(f"📁 Category path not found: {category_path}")
                continue
                
            for subcategory, processor_func in subcategories.items():
                subcategory_path = category_path / subcategory
                
                if not subcategory_path.exists():
                    self.logger.warning(f"📁 Subcategory path not found: {subcategory_path}")
                    continue
                
                # Process all CSV files in the subcategory
                for csv_file in subcategory_path.glob("*.csv"):
                    self.logger.info(f"📊 Processing dataset: {csv_file}")
                    
                    try:
                        async for log_entry in processor_func(csv_file):
                            total_entries += 1
                            yield log_entry
                            
                            # Add small delay to prevent overwhelming the system
                            if total_entries % 100 == 0:
                                await asyncio.sleep(0.1)
                                
                    except Exception as e:
                        self.logger.error(f"❌ Error processing {csv_file}: {e}")
        
        self.logger.info(f"✅ Dataset loading complete. Total entries: {total_entries}")
    
    async def _process_cicids2017(self, csv_file: Path) -> Generator[LogEntry, None, None]:
        """Process CICIDS2017 network traffic dataset"""
        df = pd.read_csv(csv_file)
        
        for _, row in df.iterrows():
            log_entry = LogEntry(
                id=str(uuid.uuid4()),
                source="CICIDS2017",
                timestamp=pd.to_datetime(row['timestamp']),
                event_type="network_traffic",
                source_ip=row['src_ip'],
                destination_ip=row['dst_ip'],
                port=row['src_port'],
                protocol=row['protocol'],
                message=f"Network flow: {row['src_ip']}:{row['src_port']} -> {row['dst_ip']}:{row['dst_port']}",
                severity=self._determine_severity(row.get('label', 'BENIGN')),
                raw_data=row.to_dict(),
                log_metadata={
                    "flow_duration": row.get('flow_duration', 0),
                    "total_fwd_packets": row.get('total_fwd_packets', 0),
                    "total_bwd_packets": row.get('total_bwd_packets', 0),
                    "flow_bytes_per_sec": row.get('flow_bytes_per_sec', 0),
                    "packet_length_mean": row.get('packet_length_mean', 0),
                    "label": row.get('label', 'BENIGN')
                }
            )
            yield log_entry
    
    async def _process_unsw_nb15(self, csv_file: Path) -> Generator[LogEntry, None, None]:
        """Process UNSW-NB15 attack patterns dataset"""
        df = pd.read_csv(csv_file)
        
        for _, row in df.iterrows():
            log_entry = LogEntry(
                id=str(uuid.uuid4()),
                source="UNSW-NB15",
                timestamp=datetime.now(),
                event_type="network_attack",
                protocol=row.get('proto', 'unknown'),
                port=row.get('service', 'unknown'),
                message=f"Network connection: {row.get('proto', 'unknown')} service={row.get('service', 'unknown')} state={row.get('state', 'unknown')}",
                severity=self._determine_severity_by_attack(row.get('attack_cat', 'Normal')),
                raw_data=row.to_dict(),
                log_metadata={
                    "duration": row.get('dur', 0),
                    "src_packets": row.get('spkts', 0),
                    "dst_packets": row.get('dpkts', 0),
                    "src_bytes": row.get('sbytes', 0),
                    "dst_bytes": row.get('dbytes', 0),
                    "attack_category": row.get('attack_cat', 'Normal'),
                    "label": row.get('label', 0)
                }
            )
            yield log_entry
    
    async def _process_windows_security(self, csv_file: Path) -> Generator[LogEntry, None, None]:
        """Process Windows Security Event logs"""
        df = pd.read_csv(csv_file)
        
        for _, row in df.iterrows():
            log_entry = LogEntry(
                id=str(uuid.uuid4()),
                source="Windows Security",
                timestamp=pd.to_datetime(row['TimeGenerated']),
                event_type=f"windows_event_{row['EventID']}",
                user=row.get('Account_Name', 'unknown'),
                source_ip=row.get('Source_Network_Address', ''),
                process=row.get('Process_Name', ''),
                message=f"EventID {row['EventID']}: {row.get('Event_Description', 'Windows security event')}",
                severity=self._map_windows_severity(row.get('Severity', 'Information')),
                raw_data=row.to_dict(),
                log_metadata={
                    "event_id": row['EventID'],
                    "computer": row.get('Computer', ''),
                    "account_domain": row.get('Account_Domain', ''),
                    "logon_type": row.get('Logon_Type', ''),
                    "process_id": row.get('Process_ID', ''),
                    "security_id": row.get('Security_ID', '')
                }
            )
            yield log_entry
    
    async def _process_android_malware(self, csv_file: Path) -> Generator[LogEntry, None, None]:
        """Process Android malware analysis dataset"""
        df = pd.read_csv(csv_file)
        
        for _, row in df.iterrows():
            log_entry = LogEntry(
                id=str(uuid.uuid4()),
                source="Android Malware Analysis",
                timestamp=pd.to_datetime(row.get('detection_date', datetime.now())),
                event_type="malware_detection",
                user=row.get('package_name', 'unknown'),
                file_path=row.get('package_name', ''),
                message=f"Malware detected: {row.get('app_name', 'Unknown')} - {row.get('malware_family', 'Unknown')}",
                severity=self._map_threat_level(row.get('threat_level', 'Medium')),
                raw_data=row.to_dict(),
                log_metadata={
                    "package_name": row.get('package_name', ''),
                    "app_name": row.get('app_name', ''),
                    "version_name": row.get('version_name', ''),
                    "file_size": row.get('file_size', 0),
                    "md5_hash": row.get('md5_hash', ''),
                    "sha256_hash": row.get('sha256_hash', ''),
                    "permissions": row.get('permissions', ''),
                    "malware_family": row.get('malware_family', ''),
                    "threat_level": row.get('threat_level', ''),
                    "behavior_analysis": row.get('behavior_analysis', ''),
                    "classification": row.get('classification', '')
                }
            )
            yield log_entry
    
    async def _process_firewall_logs(self, csv_file: Path) -> Generator[LogEntry, None, None]:
        """Process firewall syslog events"""
        df = pd.read_csv(csv_file)
        
        for _, row in df.iterrows():
            log_entry = LogEntry(
                id=str(uuid.uuid4()),
                source="Firewall",
                timestamp=pd.to_datetime(row['timestamp']),
                event_type="firewall_event",
                source_ip=row.get('src_ip', ''),
                destination_ip=row.get('dst_ip', ''),
                port=row.get('src_port', 0),
                protocol=row.get('protocol', ''),
                message=f"Firewall {row.get('action', 'UNKNOWN')}: {row.get('message', 'Firewall event')}",
                severity=self._map_firewall_severity(row.get('severity', 6)),
                raw_data=row.to_dict(),
                log_metadata={
                    "facility": row.get('facility', 16),
                    "hostname": row.get('hostname', ''),
                    "process": row.get('process', ''),
                    "action": row.get('action', ''),
                    "rule_id": row.get('rule_id', 0),
                    "bytes_in": row.get('bytes_in', 0),
                    "bytes_out": row.get('bytes_out', 0),
                    "session_id": row.get('session_id', ''),
                    "interface": row.get('interface', ''),
                    "zone_src": row.get('zone_src', ''),
                    "zone_dst": row.get('zone_dst', ''),
                    "threat_type": row.get('threat_type', ''),
                    "signature_id": row.get('signature_id', 0)
                }
            )
            yield log_entry
    
    # Placeholder methods for other dataset types
    async def _process_nsl_kdd(self, csv_file: Path) -> Generator[LogEntry, None, None]:
        """Process NSL-KDD dataset (placeholder)"""
        # Implementation similar to CICIDS2017
        return
        yield  # Make it a generator
    
    async def _process_windows_system(self, csv_file: Path) -> Generator[LogEntry, None, None]:
        """Process Windows System logs (placeholder)"""
        return
        yield  # Make it a generator
    
    async def _process_malware_samples(self, csv_file: Path) -> Generator[LogEntry, None, None]:
        """Process general malware samples (placeholder)"""
        return
        yield  # Make it a generator
    
    async def _process_router_logs(self, csv_file: Path) -> Generator[LogEntry, None, None]:
        """Process router syslog (placeholder)"""
        return
        yield  # Make it a generator
    
    async def _process_server_logs(self, csv_file: Path) -> Generator[LogEntry, None, None]:
        """Process server syslog (placeholder)"""
        return
        yield  # Make it a generator
    
    def _determine_severity(self, label: str) -> str:
        """Determine severity based on traffic label"""
        if label.upper() == 'BENIGN':
            return 'info'
        else:
            return 'high'  # Any non-benign traffic is high severity
    
    def _determine_severity_by_attack(self, attack_cat: str) -> str:
        """Determine severity based on attack category"""
        high_severity = ['DoS', 'Exploits', 'Backdoor', 'Rootkit']
        medium_severity = ['Reconnaissance', 'Fuzzers', 'Analysis']
        
        if attack_cat in high_severity:
            return 'critical'
        elif attack_cat in medium_severity:
            return 'medium'
        elif attack_cat == 'Normal':
            return 'info'
        else:
            return 'high'
    
    def _map_windows_severity(self, severity: str) -> str:
        """Map Windows event severity to standard levels"""
        mapping = {
            'Information': 'info',
            'Warning': 'medium',
            'Error': 'high',
            'Critical': 'critical'
        }
        return mapping.get(severity, 'medium')
    
    def _map_threat_level(self, threat_level: str) -> str:
        """Map malware threat level to severity"""
        mapping = {
            'Low': 'low',
            'Medium': 'medium',
            'High': 'high',
            'Critical': 'critical'
        }
        return mapping.get(threat_level, 'medium')
    
    def _map_firewall_severity(self, severity: int) -> str:
        """Map syslog severity number to standard levels"""
        # Syslog severity levels: 0=Emergency, 1=Alert, 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Info, 7=Debug
        if severity <= 2:
            return 'critical'
        elif severity <= 4:
            return 'high'
        elif severity == 5:
            return 'medium'
        else:
            return 'info'

# Singleton instance
dataset_loader = DatasetLoader()
