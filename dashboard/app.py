import os
import sys

# Ensure root path is accessible
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import glob
import json
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from src.main import run_pipeline
from src.reports.pdf_generator import generate_pdf_report

load_dotenv()

st.set_page_config(
    page_title="SOC Investigation Platform Workspace",
    layout="wide",
    page_icon="🛡️"
)

def load_cases(cases_dir="cases"):
    case_files = glob.glob(os.path.join(cases_dir, "CASE-*.json"))
    cases = []
    for cf in case_files:
        try:
            with open(cf, "r", encoding="utf-8") as f:
                cases.append(json.load(f))
        except Exception:
            pass
    cases.sort(key=lambda x: x.get("case_id", ""))
    return cases

# Header
st.title("🛡️ SOC Investigation Platform Workspace")
st.markdown("Automated Threat Detection, Correlation, Risk Scoring, ServiceNow Sync & Reporting")

# Sidebar Controls
st.sidebar.header("⚙️ SOC Workspace Controls")

# Feature 1: Live Log Upload (Drag & Drop)
st.sidebar.subheader("📂 Ingest Log Data")
uploaded_file = st.sidebar.file_uploader("Upload Event Log CSV", type=["csv"], help="Drag and drop a new Windows Security Events CSV dataset to analyze")

if uploaded_file is not None:
    target_path = os.path.join("data", "sample", "securitylab_windows_events_v2.csv")
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with open(target_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.sidebar.success(f"Uploaded `{uploaded_file.name}`! Saved as active dataset.")
    if st.sidebar.button("🔄 Analyze Uploaded Logs"):
        with st.spinner("Running detection pipeline on uploaded logs..."):
            run_pipeline()
            st.sidebar.success("Pipeline completed!")
            st.rerun()

st.sidebar.markdown("---")

# Feature 2: Trigger Pipeline Execution Button
st.sidebar.subheader("⚡ Pipeline Action")
if st.sidebar.button("▶️ Run Investigation Pipeline"):
    with st.spinner("Executing detections, correlation, scoring & ServiceNow sync..."):
        run_pipeline()
        st.success("Pipeline executed successfully!")
        st.rerun()

st.sidebar.markdown("---")

# Load Current Cases
cases = load_cases()

# Feature 3: Export PDF Report Button
st.sidebar.subheader("📄 Export Documentation")
if cases:
    pdf_bytes = generate_pdf_report(cases)
    st.sidebar.download_button(
        label="📥 Download PDF Executive Report",
        data=pdf_bytes,
        file_name="SOC_Investigation_Report.pdf",
        mime="application/pdf",
        help="Export a formal triage and investigation report containing executive summary and case breakdowns"
    )

if not cases:
    st.warning("No security cases found in `cases/`. Click 'Run Investigation Pipeline' in the sidebar or upload a dataset to begin.")
    st.stop()

# Metric Boxes
total_cases = len(cases)
high_sev = len([c for c in cases if c.get("severity") == "HIGH"])
critical = len([c for c in cases if c.get("severity") == "CRITICAL"])
true_positives = len([c for c in cases if c.get("verdict") == "TRUE_POSITIVE"])

col1, col2, col3, col4 = st.columns(4)
col1.metric("Active Cases", total_cases)
col2.metric("High Severity (7-10)", high_sev)
col3.metric("Critical Severity (11+)", critical)
col4.metric("True Positives", true_positives)

st.markdown("---")

# Summary Table
df_summary = pd.DataFrame([
    {
        "Case ID": c.get("case_id"),
        "Account": c.get("account"),
        "Source IP": c.get("source_ip"),
        "Detections": ", ".join(c.get("detections", [])),
        "Risk Score": c.get("risk_score"),
        "Severity": c.get("severity"),
        "Verdict": c.get("verdict"),
        "ServiceNow SysID": c.get("servicenow_sys_id") or "Not Synced"
    } for c in cases
])

st.subheader("📊 Active Incident Overview")
st.dataframe(df_summary, width="stretch")

st.markdown("---")

# Detail Inspector
st.subheader("🔍 Case Detail Inspector")
case_ids = [c.get("case_id") for c in cases]
selected_id = st.selectbox("Select Case ID to inspect:", case_ids)

selected_case = next(c for c in cases if c.get("case_id") == selected_id)

left_col, right_col = st.columns([1, 1])

with left_col:
    st.markdown(f"### Details for `{selected_case['case_id']}`")
    st.write(f"**Target Account:** `{selected_case['account']}`")
    st.write(f"**Source IP:** `{selected_case['source_ip']}`")
    st.write(f"**Risk Score:** `{selected_case['risk_score']}`")
    st.write(f"**Severity:** `{selected_case['severity']}`")
    st.write(f"**Verdict:** `{selected_case['verdict']}`")
    
    st.markdown("**Detections Fired:**")
    for d in selected_case.get("detections", []):
        st.markdown(f"- `{d}`")

    st.markdown("**MITRE ATT&CK Techniques:**")
    mitre_tags = " ".join([f"`{m}`" for m in selected_case.get("mitre", [])])
    st.markdown(mitre_tags if mitre_tags else "None")

    instance_url = os.getenv("SERVICENOW_INSTANCE_URL", "").rstrip("/")
    sys_id = selected_case.get("servicenow_sys_id")
    if sys_id and instance_url and "<your-instance>" not in instance_url:
        snow_link = f"{instance_url}/nav_to.do?uri=incident.do?sys_id={sys_id}"
        st.link_button("🔗 View Ticket in ServiceNow", snow_link)

with right_col:
    st.markdown("### ⏱️ Event Timeline")
    timeline = selected_case.get("timeline", [])
    if timeline:
        for ev in timeline:
            st.markdown(f"⏱️ **{ev.get('time')}** — Host: `{ev.get('host')}`")
            st.markdown(f"> {ev.get('event')}")
    else:
        st.info("No timeline events available.")

    st.markdown("### 🎯 Indicators of Compromise (IOCs)")
    iocs = selected_case.get("iocs", {})
    t_acc, t_ip, t_host = st.columns(3)
    with t_acc:
        st.markdown("**Accounts**")
        st.dataframe(pd.DataFrame({"Account": iocs.get("accounts", [])}), width="stretch")
    with t_ip:
        st.markdown("**IP Addresses**")
        st.dataframe(pd.DataFrame({"IP": iocs.get("ips", [])}), width="stretch")
    with t_host:
        st.markdown("**Hosts Touched**")
        st.dataframe(pd.DataFrame({"Host": iocs.get("hosts", [])}), width="stretch")
