import streamlit as st
import re
import faiss
import json
import requests
import numpy as np
import pandas as pd
import time
import matplotlib.pyplot as plt
from sentence_transformers import SentenceTransformer
from kubernetes import client, config
from datetime import datetime
import os
from dotenv import load_dotenv
from regex_classify import classify_with_regex
from llm_classify import classify_with_llm
from bert_classify import classify_with_bert

STORAGE_FILE = "ai_responses.json"

id = 1

load_dotenv()

# Set API keys & configurations
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_ENDPOINT = os.getenv("GROQ_ENDPOINT")

# Load Kubernetes configuration
# config.load_kube_config()
# v1 = client.CoreV1Api()

vector_dim = 384
index = faiss.IndexFlatL2(vector_dim)
log_texts = []
log_data = []
anomaly_logs = []

st.set_page_config(
    page_title="Kubernetes Anomaly Detection Dashboard",
    page_icon="🚨",
    layout="wide",
    initial_sidebar_state="expanded"
)

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

    .metric-container {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #2980b9;
        margin: 0.5rem 0;
    }

    .alert-box {
        background: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
        border-left: 4px solid #f39c12;
    }

    .success-box {
        background: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
        border-left: 4px solid #28a745;
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

    .log-container {
        background: #2d3748;
        color: #e2e8f0;
        padding: 1rem;
        border-radius: 8px;
        font-family: 'Courier New', monospace;
        max-height: 400px;
        overflow-y: auto;
        border: 1px solid #4a5568;
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

st.markdown("""
<div class="main-header">
    <h1>🚨 Kubernetes Anomaly Detection Dashboard</h1>
    <p>Real-time monitoring and AI-powered anomaly detection for your Kubernetes clusters</p>
</div>
""", unsafe_allow_html=True)

# 📌 Fetch Logs from Kubernetes API
# def fetch_live_k8s_logs():
#     logs = []
#     pods = v1.list_pod_for_all_namespaces(watch=False)
#
#     for pod in pods.items:
#         pod_name = pod.metadata.name
#         namespace = pod.metadata.namespace
#
#         try:
#             log = v1.read_namespaced_pod_log(name=pod_name, namespace=namespace)
#             logs.append({"pod": pod_name, "namespace": namespace, "log": log[:500],
#                          "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
#         except Exception:
#             pass  # Skip pods with no logs
#
#     return logs

# 📌 Fetch Logs from Kubernetes API (Your original functions remain unchanged)
def fetch_live_k8s_logs():
    logs = []

    try:
        with open("sample_logs.txt", "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():  # skip empty lines
                    logs.append({
                        "pod": "mock-pod",
                        "namespace": "default",
                        "log": line.strip(),
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
    except FileNotFoundError:
        logs.append({
            "pod": "mock-pod",
            "namespace": "default",
            "log": "No sample log file found. Please create sample_logs.txt.",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    return logs


def extract_errors_warnings(logs):
    error_patterns = [
        r'(?i)\b(error|failed|exception|crash|critical)\b',
        r'(?i)\b(timeout|unavailable|unreachable|rejected|connection refused)\b',
        r'(?i)\b(unauthorized|forbidden|access denied)\b'
    ]

    return [log for log in logs if any(re.search(pattern, log["log"]) for pattern in error_patterns)]

def classify_log(source, log_msg):
    if not log_msg or not isinstance(log_msg, str):
        return "Unclassified"

    if source == "LegacyCRM":
        return classify_with_llm(log_msg)

    label = classify_with_regex(log_msg)
    if label:
        return label

    return classify_with_bert(log_msg)

def filter_anomalous_logs(all_logs):
    """Filters logs classified as Workflow Error or Deprecation Warning."""
    filtered = []
    for log in all_logs:
        source = log.get("source", "Unknown")
        message = log.get("log", "")
        category = classify_log(source, message)
        if category in ["Workflow Error", "Deprecation Warning"]:
            filtered.append(log)
    return filtered

def detect_anomalies(filtered_logs):
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}

    if not filtered_logs:
        return "No anomalous logs to analyze."

    max_logs = 150
    trimmed_logs = filtered_logs[:max_logs]
    logs_text = "\n".join([log["log"][:500] for log in trimmed_logs])  # Truncate long logs

    payload = {
        "model": "llama3-8b-8192",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a highly accurate AI system that analyzes Kubernetes logs. "
                    "Identify anomalies, group related logs, and explain root causes."
                )
            },
            {
                "role": "user",
                "content": f"Analyze the following logs:\n\n{logs_text}"
            }
        ],
        "max_tokens": 1000
    }

    response = requests.post(GROQ_ENDPOINT, headers=headers, data=json.dumps(payload))

    if response.status_code == 200:
        return response.json()["choices"][0]["message"]["content"]
    else:
        return f"Error: {response.json().get('error', {}).get('message', 'Unknown error')}"

with st.sidebar:
    st.markdown("### 🔧 Dashboard Controls")

    st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.markdown("**⏱️ Refresh Settings**")
    refresh_interval = st.slider("Refresh Interval (seconds)", min_value=10, max_value=180, value=10)
    auto_refresh = st.checkbox("Enable Auto-refresh", value=True)
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.markdown("**📊 Display Options**")
    show_timestamps = st.checkbox("Show Timestamps", value=True)
    max_logs_display = st.number_input("Max Logs to Display", min_value=10, max_value=1000, value=100)
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.markdown("**🎯 Filter Options**")
    filter_errors_only = st.checkbox("Show Errors/Warnings Only", value=False)
    pod_filter = st.text_input("Filter by Pod", placeholder="mock-pod")
    st.markdown('</div>', unsafe_allow_html=True)
    view_saved = st.checkbox("📁 View Saved AI Responses")

if st.sidebar.button("🗑️ Clear Stored AI Response"):
    if os.path.exists(STORAGE_FILE):
        os.remove(STORAGE_FILE)
        st.success("Cached AI response cleared. Reload to fetch new one.")

col1, col2 = st.columns([2, 1])

with col2:
    st.markdown("### 📈 System Status")

    logs = fetch_live_k8s_logs()
    error_logs = extract_errors_warnings(logs)

    total_logs = len(logs)
    error_count = len(error_logs)
    healthy_logs = total_logs - error_count

    if error_count == 0:
        status = "healthy"
        status_color = "status-healthy"
        status_text = "Healthy"
    elif error_count / total_logs < 0.1:
        status = "warning"
        status_color = "status-warning"
        status_text = "Warning"
    else:
        status = "error"
        status_color = "status-error"
        status_text = "Critical"

    st.markdown(f"""
    <div class="card">
        <h4><span class="status-indicator {status_color}"></span>Cluster Status: {status_text}</h4>
        <p><strong>Last Updated:</strong> {datetime.now().strftime("%H:%M:%S")}</p>
    </div>
    """, unsafe_allow_html=True)

    col_a, col_b = st.columns(2)
    with col_a:
        st.metric("Total Logs", total_logs, delta=None)
    with col_b:
        st.metric("Errors/Warnings", error_count, delta=None)

    st.metric("Healthy Logs", healthy_logs, delta=None)

st.markdown("---")

def save_ai_response(response_text):
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

    max_index = max((item.get("index", 0) for item in existing), default=0) + 1
    entry["index"] = max_index

    existing.insert(0, entry)  
    with open(STORAGE_FILE, "w") as f:
        json.dump(existing, f, indent=2)



def load_all_saved_responses():
    if os.path.exists(STORAGE_FILE):
        with open(STORAGE_FILE, "r") as f:
            return json.load(f)
    return []

st.markdown("### 🚨 Anomaly Detection")

cached_response = load_all_saved_responses()

with st.spinner("🔍 Detecting anomalies..."):
    anomaly_logs = detect_anomalies(logs)

    if not anomaly_logs.startswith("Error:"):
        save_ai_response(anomaly_logs)
        st.markdown("✅ New AI anomaly analysis generated and saved.")
    else:
        st.error(anomaly_logs)

if "Error:" in str(anomaly_logs):
    st.markdown(f'<div class="error-box"><strong>⚠️ AI Service Error:</strong><br>{anomaly_logs}</div>',
                unsafe_allow_html=True)
else:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**🤖 AI Anomaly Analysis:**")
    st.write(anomaly_logs)
    st.markdown('</div>', unsafe_allow_html=True)

if view_saved:
    st.markdown("## 📁 Saved AI Anomaly Responses")
    saved_responses = load_all_saved_responses()

    if not saved_responses:
        st.info("No saved responses found yet.")
    else:
        for item in saved_responses:
            if isinstance(item, dict) and "timestamp" in item and "response" in item:
                index_display = item.get("index", "N/A")
                with st.expander(f"🗂️ Index: {index_display} — 🕒 {item['timestamp']}"):
                    st.write(item["response"])


st.markdown("### 📄 Live Kubernetes Logs")

display_logs = logs

if filter_errors_only:
    display_logs = error_logs

if pod_filter: 
    display_logs = [log for log in display_logs if pod_filter.lower() in log['pod'].lower()]


display_logs = display_logs[:max_logs_display]

if display_logs:
    df = pd.DataFrame(display_logs)


    def get_log_status(log_text):
        error_patterns = [r'(?i)\b(error|failed|exception|crash|critical)\b']
        if any(re.search(pattern, log_text) for pattern in error_patterns):
            return "🔴 Error"
        elif any(word in log_text.lower() for word in ['warn', 'warning']):
            return "🟡 Warning"
        else:
            return "🟢 Info"


    df['Status'] = df['log'].apply(get_log_status)

    if show_timestamps:
        df = df[['Status', 'timestamp', 'pod', 'namespace', 'log']]
    else:
        df = df[['Status', 'pod', 'namespace', 'log']]

    st.dataframe(
        df,
        use_container_width=True,
        height=400,
        column_config={
            "Status": st.column_config.TextColumn("Status", width="small"),
            "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
            "pod": st.column_config.TextColumn("Pod", width="medium"),
            "namespace": st.column_config.TextColumn("Namespace", width="small"),
            "log": st.column_config.TextColumn("Log Message", width="large")
        }
    )
else:
    st.markdown('<div class="alert-box">📋 <strong>No logs to display</strong> based on current filters.</div>',
                unsafe_allow_html=True)

if auto_refresh:
    st.markdown("---")
    st.markdown(f"🔄 **Auto-refresh enabled** - Next update in {refresh_interval} seconds")
    time.sleep(refresh_interval)
    st.rerun()
else:
    st.markdown("---")
    if st.button("🔄 Manual Refresh", type="primary"):
        st.rerun()
