# Kubernetes Log Anomaly Detection

A comprehensive Kubernetes log anomaly detection system that identifies anomalous logs and performs root cause analysis using advanced ML techniques and LLM integration.

## Overview

This project implements a two-stage anomaly detection pipeline:

1. **Anomaly Detection & Classification**: Filters and classifies anomalous logs from Kubernetes clusters using:
   - Regex pattern matching
   - Text embeddings
   - Large Language Model (LLM) analysis

2. **Root Cause Analysis**: Processes detected anomalies through LLM to identify root causes and generate detailed reports

## Features

- **Dual Log Fetching**: Support for both sample logs and live Kubernetes API integration
- **Multi-layered Detection**: Combines regex, embeddings, and LLM for accurate anomaly detection
- **Root Cause Analysis**: Automated analysis and reporting of detected anomalies
- **Streamlit Interface**: User-friendly web interface for monitoring and analysis
- **Real-time Processing**: Live log monitoring from Kubernetes clusters

## Prerequisites

- Python 3.8+
- Kubernetes cluster access (for live log fetching)
- kubectl configured (for Kubernetes API access)
- GROQ API access

## Installation

1. Clone the repository:
```bash
git clone [(https://github.com/Nikhilg27425/K8s_anamoly_detection)]
cd K8s_anomaly_detection
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables (see Configuration section below)

## Configuration

Create a `.env` file in the project root directory:

```env
# GROQ API Configuration
GROQ_API_KEY=your_groq_api_key_here
GROQ_ENDPOINT=https://api.groq.com/openai/v1

# Kubernetes Configuration (optional - for live log fetching)
KUBECONFIG_PATH=/path/to/your/kubeconfig
NAMESPACE=default
LOG_LEVEL=INFO

# Application Settings
MAX_LOG_ENTRIES=1000
ANOMALY_THRESHOLD=0.8
EMBEDDING_MODEL=all-MiniLM-L6-v2
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GROQ_API_KEY` | Your GROQ API key for LLM processing | Yes |
| `GROQ_ENDPOINT` | GROQ API endpoint URL | Yes |
| `KUBECONFIG_PATH` | Path to Kubernetes config file | Optional |
| `NAMESPACE` | Kubernetes namespace to monitor | Optional |
| `LOG_LEVEL` | Application logging level | Optional |

## Usage

### Running the Application

Start the Streamlit application:

```bash
streamlit run app.py
```

The application will be available at `http://localhost:8501`

### Log Fetching Options

The application provides two methods for log retrieval:

#### 1. Sample Log Analysis
- **Purpose**: Analyze pre-collected or uploaded log files
- **Usage**: 
  - Select "Sample Logs" in the Streamlit interface
  - Upload your log file or use provided sample data
  - Ideal for testing and analyzing historical logs

#### 2. Live Kubernetes Log Fetching
- **Purpose**: Real-time monitoring of Kubernetes cluster logs
- **Prerequisites**: 
  - Kubernetes cluster access
  - Proper RBAC permissions
  - kubectl configured
- **Usage**:
  - Select "Live Logs" in the Streamlit interface
  - Configure namespace and pod filters
  - Monitor real-time anomalies as they occur

### Workflow

1. **Log Input**: Choose between sample logs or live Kubernetes logs
2. **Anomaly Detection**: The system processes logs through:
   - Regex pattern matching for known error patterns
   - Embedding-based similarity analysis
   - LLM-powered anomaly classification
3. **Root Cause Analysis**: Detected anomalies are analyzed by LLM
4. **Report Generation**: Comprehensive reports with:
   - Anomaly details
   - Root cause analysis
   - Recommended actions
   - Severity assessment

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Log Sources   │    │   Anomaly        │    │   Root Cause    │
│                 │───▶│   Detection      │───▶│   Analysis      │
│ • Sample Logs   │    │                  │    │                 │
│ • Live K8s Logs │    │ • Regex          │    │ • LLM Analysis  │
└─────────────────┘    │ • Embeddings     │    │ • Report Gen    │
                       │ • LLM Classify   │    └─────────────────┘
                       └──────────────────┘
```

## API Endpoints

When running via Streamlit, the following functionality is available:

- **Dashboard**: Overview of detected anomalies
- **Log Analysis**: Real-time log processing and anomaly detection
- **Reports**: Generated root cause analysis reports
- **Configuration**: System settings and parameters

## Kubernetes RBAC

For live log fetching, ensure your Kubernetes service account has appropriate permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: log-reader
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: log-reader-binding
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
roleRef:
  kind: ClusterRole
  name: log-reader
  apiGroup: rbac.authorization.k8s.io
```

## Troubleshooting

### Common Issues

1. **GROQ API Connection Issues**
   - Verify your API key in the `.env` file
   - Check network connectivity to GROQ endpoints

2. **Kubernetes Access Issues**
   - Ensure kubectl is properly configured
   - Verify RBAC permissions for log access
   - Check namespace accessibility

3. **Performance Issues**
   - Adjust `MAX_LOG_ENTRIES` for large log volumes
   - Consider filtering logs by severity or time range

### Logs and Debugging

Enable debug logging by setting:
```env
LOG_LEVEL=DEBUG
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Create an issue in the GitHub repository
- Check the troubleshooting section above
- Review the logs for detailed error information
