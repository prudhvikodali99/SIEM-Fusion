# SIEM-Fusion Architecture Documentation

## System Overview

SIEM-Fusion is designed as a modular, scalable system that processes security logs through a coordinated Multi-LLM pipeline. The architecture follows a microservices approach with clear separation of concerns.

## High-Level Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Data Sources  │    │   Collectors    │    │  Normalization  │
│                 │───▶│                 │───▶│                 │
│ • Syslog        │    │ • SyslogCollector│    │ • LogNormalizer │
│ • MySQL         │    │ • MySQLCollector │    │ • Schema        │
│ • Windows Events│    │ • WindowsCollector│   │   Standardization│
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                                                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Multi-LLM Processing Pipeline                │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐│
│  │   LLM-1     │  │   LLM-2     │  │   LLM-3     │  │  LLM-4  ││
│  │  Anomaly    │─▶│   Threat    │─▶│ Contextual  │─▶│ Alert   ││
│  │ Detection   │  │Intelligence │  │Correlation  │  │Generation││
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘│
└─────────────────────────────────────────────────────────────────┘
                                                        │
                                                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Database      │    │  SOC Dashboard  │    │   API Gateway   │
│                 │◀───│                 │◀───│                 │
│ • Alerts        │    │ • Visualization │    │ • REST API      │
│ • Logs          │    │ • Filtering     │    │ • WebSocket     │
│ • Metrics       │    │ • Management    │    │ • Authentication│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Component Details

### 1. Data Collection Layer

#### Collectors
- **SyslogCollector**: Receives syslog messages via UDP/TCP
- **MySQLCollector**: Polls database for new security events
- **WindowsCollector**: Retrieves Windows Event Log entries
- **CollectorManager**: Orchestrates all collectors

#### Design Patterns
- **Strategy Pattern**: Different collection strategies for each source
- **Observer Pattern**: Async event notification
- **Factory Pattern**: Dynamic collector instantiation

### 2. Processing Layer

#### Log Normalization
```python
RawLogEntry → LogNormalizer → NormalizedLogEntry
```

**Normalization Process:**
1. Parse source-specific formats
2. Extract common fields (IP, user, timestamp, etc.)
3. Apply standardized schema
4. Generate tags and metadata

#### Multi-LLM Pipeline

**Sequential Processing:**
```
NormalizedLogs → LLM-1 → AnomalyResults → LLM-2 → ThreatResults → LLM-3 → CorrelationResults → LLM-4 → Alerts
```

**LLM Coordination:**
- Each LLM has a specific role and expertise
- Output of one LLM becomes input for the next
- Parallel processing within batches
- Error handling and fallback mechanisms

### 3. LLM Integration Layer

#### Base LLM Architecture
```python
class BaseLLM:
    - Provider abstraction (OpenAI, Anthropic)
    - Prompt engineering
    - Response parsing
    - Error handling
    - Rate limiting
```

#### Specialized LLMs

**LLM-1: Anomaly Detection**
- **Input**: Normalized log entries
- **Processing**: Pattern recognition, statistical analysis
- **Output**: Anomaly scores and classifications

**LLM-2: Threat Intelligence**
- **Input**: Anomalous events + threat intel context
- **Processing**: IoC matching, threat verification
- **Output**: Threat scores and matched indicators

**LLM-3: Contextual Correlation**
- **Input**: Verified threats + historical data
- **Processing**: Event correlation, business context
- **Output**: Enriched threat objects with correlations

**LLM-4: Alert Generation**
- **Input**: Correlated threats + business impact
- **Processing**: Risk assessment, alert prioritization
- **Output**: Actionable security alerts

### 4. Data Layer

#### Database Schema
```sql
-- Core entities
log_entries (id, source, timestamp, event_type, ...)
alerts (id, title, severity, status, ...)
alert_log_mapping (alert_id, log_id)
processing_metrics (timestamp, stage, metrics)
```

#### Data Flow
1. **Ingestion**: Raw logs → Database
2. **Processing**: Batch retrieval → LLM pipeline
3. **Storage**: Results → Database
4. **Presentation**: Database → Dashboard

### 5. Presentation Layer

#### SOC Dashboard
- **Technology**: Dash + Plotly
- **Features**: Real-time updates, filtering, visualization
- **Architecture**: Component-based UI with callbacks

#### API Layer
- **REST API**: CRUD operations for alerts
- **WebSocket**: Real-time updates
- **Authentication**: Token-based security

## Data Flow

### 1. Log Ingestion Flow
```
External System → Collector → Buffer → Normalization → Database
```

### 2. Processing Flow
```
Database → Batch Retrieval → LLM Pipeline → Alert Generation → Database
```

### 3. Presentation Flow
```
Database → API → Dashboard → User Interface
```

## Scalability Considerations

### Horizontal Scaling
- **Collectors**: Multiple instances per source type
- **Processing**: Distributed LLM processing
- **Database**: Read replicas, sharding
- **Dashboard**: Load balancing

### Performance Optimization
- **Batching**: Process logs in configurable batches
- **Caching**: Redis for frequently accessed data
- **Async Processing**: Non-blocking I/O operations
- **Connection Pooling**: Database connection management

### Resource Management
- **Memory**: Bounded queues and buffers
- **CPU**: Configurable concurrency limits
- **Network**: Rate limiting and retry logic
- **Storage**: Data retention policies

## Security Architecture

### Authentication & Authorization
- **API Keys**: Secure LLM provider access
- **Environment Variables**: Sensitive configuration
- **Role-Based Access**: Dashboard user permissions

### Data Security
- **Encryption**: In-transit and at-rest
- **Sanitization**: Log data cleaning
- **Audit Logging**: System activity tracking
- **Compliance**: GDPR, SOX, HIPAA considerations

### Network Security
- **Firewall Rules**: Collector port restrictions
- **TLS/SSL**: Encrypted communications
- **VPN**: Secure remote access
- **Network Segmentation**: Isolated processing

## Monitoring & Observability

### Metrics Collection
- **System Metrics**: CPU, memory, disk usage
- **Application Metrics**: Processing rates, error counts
- **Business Metrics**: Alert quality, false positive rates

### Logging Strategy
- **Structured Logging**: JSON format with correlation IDs
- **Log Levels**: DEBUG, INFO, WARN, ERROR, CRITICAL
- **Log Aggregation**: Centralized log collection

### Health Checks
- **Component Health**: Individual service status
- **Dependency Health**: External service availability
- **End-to-End Health**: Complete pipeline validation

## Deployment Architecture

### Development Environment
```
Local Machine → Docker Compose → SQLite → Local Dashboard
```

### Production Environment
```
Load Balancer → Application Servers → PostgreSQL Cluster → Redis Cluster
```

### Cloud Deployment
- **Containerization**: Docker images
- **Orchestration**: Kubernetes
- **Service Mesh**: Istio for communication
- **Monitoring**: Prometheus + Grafana

## Configuration Management

### Configuration Hierarchy
1. **Default Values**: Built-in defaults
2. **Configuration File**: config.yaml
3. **Environment Variables**: Runtime overrides
4. **Command Line**: Startup parameters

### Environment-Specific Configs
- **Development**: Debug logging, mock data
- **Staging**: Production-like with test data
- **Production**: Optimized performance settings

## Error Handling & Recovery

### Error Categories
- **Transient Errors**: Network timeouts, rate limits
- **Permanent Errors**: Invalid configuration, missing resources
- **Partial Failures**: Some components failing

### Recovery Strategies
- **Retry Logic**: Exponential backoff
- **Circuit Breakers**: Prevent cascade failures
- **Graceful Degradation**: Reduced functionality
- **Failover**: Backup systems activation

## Future Enhancements

### Planned Features
- **Machine Learning**: Adaptive threat detection
- **Integration**: SOAR platform connectivity
- **Analytics**: Advanced threat hunting
- **Automation**: Response orchestration

### Scalability Roadmap
- **Microservices**: Further decomposition
- **Event Streaming**: Kafka integration
- **Multi-Tenant**: SaaS deployment model
- **Edge Computing**: Distributed processing
