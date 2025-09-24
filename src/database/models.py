from sqlalchemy import Column, String, DateTime, Float, Integer, Text, JSON, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class LogEntry(Base):
    """Database model for normalized log entries"""
    __tablename__ = "log_entries"
    
    id = Column(String, primary_key=True)
    source = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)
    source_ip = Column(String, index=True)
    destination_ip = Column(String, index=True)
    user = Column(String, index=True)
    process = Column(String)
    command = Column(Text)
    file_path = Column(String)
    port = Column(Integer)
    protocol = Column(String)
    status_code = Column(Integer)    # Core log data
    message = Column(Text, nullable=False)
    severity = Column(String, default="info")  # info, low, medium, high, critical
    tags = Column(JSON)  # For flexible tagging
    log_metadata = Column(JSON)  # Additional structured data (renamed from metadata)
    raw_data = Column(JSON)  # Store original raw log data
    created_at = Column(DateTime, default=datetime.utcnow)

class AlertEntry(Base):
    """Database model for alerts"""
    __tablename__ = "alerts"
    
    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    entities = Column(JSON)
    attack_vector = Column(String)
    recommended_actions = Column(JSON)
    status = Column(String, nullable=False, default="new", index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    analyst_notes = Column(Text)
    false_positive_reason = Column(Text)
    
    # Relationships
    source_logs = relationship("AlertLogMapping", back_populates="alert")

class AlertLogMapping(Base):
    """Mapping table between alerts and source log entries"""
    __tablename__ = "alert_log_mapping"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String, ForeignKey("alerts.id"), nullable=False)
    log_id = Column(String, ForeignKey("log_entries.id"), nullable=False)
    
    # Relationships
    alert = relationship("AlertEntry", back_populates="source_logs")
    log = relationship("LogEntry")

class ProcessingMetrics(Base):
    """Database model for processing metrics and statistics"""
    __tablename__ = "processing_metrics"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    total_logs_processed = Column(Integer, default=0)
    anomalies_detected = Column(Integer, default=0)
    threats_verified = Column(Integer, default=0)
    alerts_generated = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)
    processing_time_avg = Column(Float, default=0.0)
    pipeline_stage = Column(String)  # Which stage the metrics are for
    additional_metrics = Column(JSON)  # For extensibility
