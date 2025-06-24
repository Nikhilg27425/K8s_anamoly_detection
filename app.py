import streamlit as st
import re
import json
import requests
import pandas as pd
import time
from kubernetes import client, config
from datetime import datetime
import os
from dotenv import load_dotenv
from regex_classify import classify_with_regex
from llm_classify import classify_with_llm
from bert_classify import classify_with_bert

STORAGE_FILE = "ai_responses.json"

load_dotenv()

# Set API keys & configurations
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_ENDPOINT = os.getenv("GROQ_ENDPOINT")

#Load Kubernetes configuration
# config.load_kube_config()
# v1 = client.CoreV1Api()

# Enhanced Streamlit UI Setup
st.set_page_config(
    page_title="Kubernetes Anomaly Detection Dashboard",
    page_icon="🚨",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1f4e79 0%, #2980b9 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }

    .alert-box {
        background: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
        border-left: 4px solid #f39c12;
    }

    .error-box {
        background: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
        border-left: 4px solid #dc3545;
    }

    .sidebar-section {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
        border: 1px solid #e9ecef;
    }

    .status-indicator {
        display: inline-block;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        margin-right: 8px;
    }

    .status-healthy { background-color: #28a745; }
    .status-warning { background-color: #ffc107; }
    .status-error { background-color: #dc3545; }

    .card {
        background: white;
        color: black;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        border: 1px solid #e9ecef;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# Header Section
st.markdown("""
<div class="main-header">
    <h1>🚨 Kubernetes Anomaly Detection Dashboard</h1>
    <p>Real-time monitoring and AI-powered anomaly detection for your Kubernetes clusters</p>
</div>
""", unsafe_allow_html=True)


# 📌 Fetch Live Logs from Kubernetes API
def fetch_live_k8s_logs():
    """Fetch live logs from Kubernetes API"""
    logs = []
    pods = v1.list_pod_for_all_namespaces(watch=False)

    for pod in pods.items:
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace

        try:
            # Get the last 100 lines of the pod log
            log_response = v1.read_namespaced_pod_log(
                name=pod_name,
                namespace=namespace,
                tail_lines=100
            )

            # Split logs into individual lines
            log_lines = log_response.strip().split('\n')

            for line in log_lines:
                if line.strip():  # Skip empty lines
                    logs.append({
                        "pod": pod_name,
                        "namespace": namespace,
                        "log": line.strip(),
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "source": "Kubernetes"
                    })

        except Exception as e:
            st.error(f"❌ Failed to fetch logs for {pod_name}: {e}")
            continue

    return logs


# 📌 Fallback function for sample logs (kept for testing)
def fetch_sample_logs():
    """Fetch sample logs from file (for testing purposes)"""
    logs = []
    try:
        with open("sample_logs.txt", "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():  # skip empty lines
                    logs.append({
                        "pod": "mock-pod",
                        "namespace": "default",
                        "log": line.strip(),
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "source": "Sample"
                    })
    except FileNotFoundError:
        logs.append({
            "pod": "mock-pod",
            "namespace": "default",
            "log": "No sample log file found. Please create sample_logs.txt.",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": "Sample"
        })

    return logs


# 📌 Log Classification Function
def classify_log(source, log_msg):
    """Classify logs using the appropriate classification method"""
    if not log_msg or not isinstance(log_msg, str):
        return "Unclassified"

    # Use LLM classification for LegacyCRM logs
    if source == "LegacyCRM":
        return classify_with_llm(log_msg)

    # Try regex classification first
    label = classify_with_regex(log_msg)
    if label and label != "Unclassified":
        return label

    # Fallback to BERT classification
    return classify_with_bert(log_msg)


# 📌 Filter logs that are classified as anomalies
def filter_anomalous_logs(all_logs):
    """Filter logs classified as Workflow Error or Deprecation Warning (anomalies)"""
    anomalous_logs = []

    for log in all_logs:
        source = log.get("source", "Unknown")
        message = log.get("log", "")

        # Classify the log
        category = classify_log(source, message)

        # Add classification to the log entry
        log["classification"] = category

        # Filter for anomalous categories
        if any(word in category.lower() for word in ["error", "warning"]):
            anomalous_logs.append(log)

    return anomalous_logs


# 📌 Generate AI Report for Anomalous Logs
def generate_anomaly_report(anomalous_logs):
    """Send anomalous logs to LLM for analysis and report generation"""
    if not anomalous_logs:
        return "No anomalous logs detected."

    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}

    # Limit logs for API call
    max_logs = 50
    trimmed_logs = anomalous_logs[:max_logs]

    # Format logs for analysis
    logs_text = "\n".join([
        f"[{log['classification']}] Pod: {log['pod']} | Namespace: {log['namespace']} | Message: {log['log'][:300]}"
        for log in trimmed_logs
    ])

    payload = {
        "model": "llama3-8b-8192",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert Kubernetes administrator analyzing anomalous logs. "
                    "The logs provided are already classified as 'Workflow Error' or 'Deprecation Warning'. "
                    "Analyze these anomalies, identify patterns, group related issues, and provide actionable insights. "
                    "Focus on root cause analysis and remediation suggestions."
                )
            },
            {
                "role": "user",
                "content": f"Analyze these anomalous Kubernetes logs and provide a detailed report:\n\n{logs_text}"
            }
        ],
        "max_tokens": 1200
    }

    try:
        response = requests.post(GROQ_ENDPOINT, headers=headers, data=json.dumps(payload))

        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        else:
            return f"Error: {response.json().get('error', {}).get('message', 'Unknown error')}"
    except Exception as e:
        return f"API Error: {str(e)}"


# 📌 Save AI Response
def save_ai_response(response_text):
    """Save AI analysis response to file"""
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "response": response_text
    }

    existing = []
    if os.path.exists(STORAGE_FILE):
        with open(STORAGE_FILE, "r") as f:
            try:
                existing = json.load(f)
                if not isinstance(existing, list):
                    existing = [existing]
            except json.JSONDecodeError:
                existing = []

    # Assign index
    max_index = max((item.get("index", 0) for item in existing), default=0) + 1
    entry["index"] = max_index

    existing.insert(0, entry)  # newest first
    with open(STORAGE_FILE, "w") as f:
        json.dump(existing, f, indent=2)


# 📌 Load Saved Responses
def load_all_saved_responses():
    """Load all saved AI responses"""
    if os.path.exists(STORAGE_FILE):
        with open(STORAGE_FILE, "r") as f:
            return json.load(f)
    return []


# Sidebar Controls
with st.sidebar:
    st.markdown("### 🔧 Dashboard Controls")

    st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.markdown("**⏱️ Refresh Settings**")
    refresh_interval = st.slider("Refresh Interval (seconds)", min_value=10, max_value=180, value=30)
    auto_refresh = st.checkbox("Enable Auto-refresh", value=False)
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.markdown("**📊 Display Options**")
    show_timestamps = st.checkbox("Show Timestamps", value=True)
    max_logs_display = st.number_input("Max Logs to Display", min_value=10, max_value=500, value=100)
    use_sample_logs = st.checkbox("Use Sample Logs (for testing)", value=False)
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.markdown("**🎯 Filter Options**")
    pod_filter = st.text_input("Filter by Pod Name", placeholder="Enter pod name...")
    namespace_filter = st.text_input("Filter by Namespace", placeholder="Enter namespace...")
    st.markdown('</div>', unsafe_allow_html=True)

    view_saved = st.checkbox("📁 View Saved AI Reports")

    if st.button("🗑️ Clear Stored AI Reports"):
        if os.path.exists(STORAGE_FILE):
            os.remove(STORAGE_FILE)
            st.success("Cached AI reports cleared!")

# Main Content
try:
    # Fetch logs
    if use_sample_logs:
        st.info("📝 Using sample logs for testing")
        all_logs = fetch_sample_logs()
    else:
        st.info("🔗 Fetching live logs from Kubernetes API")
        all_logs = fetch_live_k8s_logs()

    filtered_logs = all_logs
    if pod_filter:
        filtered_logs = [log for log in filtered_logs if pod_filter.lower() in log['pod'].lower()]
    if namespace_filter:
        filtered_logs = [log for log in filtered_logs if namespace_filter.lower() in log['namespace'].lower()]

    # Classify and filter anomalous logs
    with st.spinner("🔍 Classifying logs and detecting anomalies..."):
        anomalous_logs = filter_anomalous_logs(filtered_logs)

    # Display metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Logs", len(all_logs))
    with col2:
        st.metric("Filtered Logs", len(filtered_logs)- len(anomalous_logs))
    with col3:
        st.metric("Anomalous Logs", len(anomalous_logs))

    # Generate and display anomaly report
    st.markdown("### 🚨 Anomaly Analysis Report")

    if anomalous_logs:
        with st.spinner("🤖 Generating AI analysis report..."):
            anomaly_report = generate_anomaly_report(anomalous_logs)

        if not anomaly_report.startswith("Error:") and not anomaly_report.startswith("API Error:"):
            save_ai_response(anomaly_report)
            st.success("✅ New anomaly analysis report generated and saved.")

        # Display the report
        if "Error:" in anomaly_report or "API Error:" in anomaly_report:
            st.markdown(f'<div class="error-box"><strong>⚠️ AI Service Error:</strong><br>{anomaly_report}</div>',
                        unsafe_allow_html=True)
        else:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown("**🤖 AI Anomaly Analysis Report:**")
            st.write(anomaly_report)
            st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="alert-box">✅ <strong>No anomalies detected</strong> in the current logs.</div>',
                    unsafe_allow_html=True)

    # Display saved reports if requested
    if view_saved:
        st.markdown("## 📁 Saved AI Anomaly Reports")
        saved_responses = load_all_saved_responses()

        if not saved_responses:
            st.info("No saved reports found yet.")
        else:
            for item in saved_responses:
                if isinstance(item, dict) and "timestamp" in item and "response" in item:
                    index_display = item.get("index", "N/A")
                    with st.expander(f"🗂️ Report #{index_display} — 🕒 {item['timestamp']}"):
                        st.write(item["response"])

    # Display logs table
    st.markdown("### 📄 Kubernetes Logs")

    if filtered_logs:
        # Limit displayed logs
        display_logs = filtered_logs[:max_logs_display]

        # Create DataFrame
        df = pd.DataFrame(display_logs)


        # Add status indicators
        def get_log_status(classification):
            if classification in ["Workflow Error", "Deprecation Warning"]:
                return "🔴 Anomaly"
            elif "error" in classification.lower() or "warning" in classification.lower():
                return "🟡 Warning"
            else:
                return "🟢 Normal"


        df['Status'] = df.get('classification', 'Unclassified').apply(get_log_status)

        # Reorder columns
        columns = ['Status', 'classification']
        if show_timestamps:
            columns.append('timestamp')
        columns.extend(['pod', 'namespace', 'log'])

        df = df[columns]

        # Display table
        st.dataframe(
            df,
            use_container_width=True,
            height=400,
            column_config={
                "Status": st.column_config.TextColumn("Status", width="small"),
                "classification": st.column_config.TextColumn("Classification", width="medium"),
                "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "pod": st.column_config.TextColumn("Pod", width="medium"),
                "namespace": st.column_config.TextColumn("Namespace", width="small"),
                "log": st.column_config.TextColumn("Log Message", width="large")
            }
        )
    else:
        st.markdown('<div class="alert-box">📋 <strong>No logs to display</strong> based on current filters.</div>',
                    unsafe_allow_html=True)

except Exception as e:
    st.error(f"❌ Error connecting to Kubernetes API: {str(e)}")
    st.info("💡 Try enabling 'Use Sample Logs' in the sidebar for testing.")

# Footer with refresh options
st.markdown("---")
if auto_refresh:
    st.markdown(f"🔄 **Auto-refresh enabled** - Next update in {refresh_interval} seconds")
    time.sleep(refresh_interval)
    st.rerun()
else:
    if st.button("🔄 Manual Refresh", type="primary"):
        st.rerun()
