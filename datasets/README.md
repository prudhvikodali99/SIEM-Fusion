# 📊 SIEM-Fusion Security Datasets

This directory contains security datasets for testing and training the SIEM-Fusion multi-LLM pipeline.

## 📁 Directory Structure:

```
datasets/
├── network_intrusion/
│   ├── CICIDS2017/
│   ├── UNSW-NB15/
│   └── NSL-KDD/
├── malware/
│   ├── samples/
│   └── analysis/
├── windows_events/
│   ├── security_logs/
│   └── system_logs/
├── syslog/
│   ├── firewall/
│   ├── router/
│   └── server/
└── processed/
    ├── normalized/
    └── analyzed/
```

## 🎯 **Dataset Placement Guide:**

### Network Intrusion Detection:
- **CICIDS2017**: Place CSV files in `network_intrusion/CICIDS2017/`
- **UNSW-NB15**: Place CSV files in `network_intrusion/UNSW-NB15/`
- **NSL-KDD**: Place CSV files in `network_intrusion/NSL-KDD/`

### Malware Samples:
- **MalDroid 2020**: Place in `malware/samples/android/`
- **Other malware**: Place in `malware/samples/`

### Log Files:
- **Windows Event Logs**: Place in `windows_events/`
- **Syslog samples**: Place in `syslog/`

## 🔄 **Processing Pipeline:**

1. **Raw datasets** → `datasets/[category]/`
2. **Normalized data** → `datasets/processed/normalized/`
3. **LLM analyzed** → `datasets/processed/analyzed/`

## 📝 **Usage:**

The SIEM-Fusion system will automatically detect and process datasets from these directories.
Configure the data paths in `config.yaml` under the `data_sources` section.
