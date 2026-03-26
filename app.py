"""
Project Agentic SecOps — Streamlit Dashboard (app.py)

Run:  streamlit run app.py
"""

from __future__ import annotations

import sys
import os
print("="*20)
print("PYTHON SYS.PATH:")
for p in sys.path:
    print(p)
print("="*20)
# Attempt to find the correct site-packages directory
try:
    # Based on the venv structure, the executable is in venv/bin/python
    # So site-packages should be in ../lib/pythonX.Y/site-packages
    # We'll try to be robust to the exact python version
    py_executable_dir = os.path.dirname(sys.executable)
    venv_dir = os.path.dirname(py_executable_dir)
    lib_dir = os.path.join(venv_dir, 'lib')
    
    # Find the pythonX.Y directory
    python_version_dir = ""
    for d in os.listdir(lib_dir):
        if d.startswith('python'):
            python_version_dir = d
            break
            
    if python_version_dir:
        site_packages_path = os.path.join(lib_dir, python_version_dir, 'site-packages')
        print(f"LISTING {site_packages_path}:")
        for item in os.listdir(site_packages_path):
            print(f"  - {item}")
    else:
        print("Could not find pythonX.Y directory in lib.")

except Exception as e:
    print(f"Could not list site-packages: {e}")
print("="*20)

import json
import time
import sys
import os
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(override=True)

import streamlit as st

# ── Page config — must be first Streamlit call ─────────────────────────────────
st.set_page_config(
    page_title="Agentic SecOps | SOC AIOps",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Inject global CSS ──────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

/* Light theme overrides + reduced padding to fit on screen */
.block-container {
    padding-top: 1rem !important;
    padding-bottom: 1rem !important;
    max-width: 98% !important;
}
.stApp { background: #f8fafc; color: #0f172a; }
.stSidebar { background: #ffffff !important; border-right: 1px solid #e2e8f0; }
.stSidebar .stMarkdown { color: #475569; }

/* Cards */
.secops-card {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 16px;
    margin: 8px 0;
    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
}
.secops-card-header {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1.5px;
    color: #2563eb;
    text-transform: uppercase;
    margin-bottom: 6px;
}

/* Severity badges */
.badge-critical { background:#fef2f2; color:#b91c1c; border:1px solid #f87171; padding:2px 8px; border-radius:12px; font-size:11px; font-weight:700; }
.badge-high     { background:#fff7ed; color:#c2410c; border:1px solid #fb923c; padding:2px 8px; border-radius:12px; font-size:11px; font-weight:700; }
.badge-medium   { background:#fefce8; color:#a16207; border:1px solid #facc15; padding:2px 8px; border-radius:12px; font-size:11px; font-weight:700; }
.badge-low      { background:#f0fdf4; color:#15803d; border:1px solid #4ade80; padding:2px 8px; border-radius:12px; font-size:11px; font-weight:700; }

/* Agent message colours */
.msg-orchestrator { border-left: 3px solid #0284c7; background:#f0f9ff; padding:4px 10px; border-radius:4px; margin:2px 0; font-size:12px; font-family:'JetBrains Mono',monospace; }
.msg-case-retrieval{ border-left: 3px solid #16a34a; background:#f0fdf4; padding:4px 10px; border-radius:4px; margin:2px 0; font-size:12px; font-family:'JetBrains Mono',monospace; }
.msg-rag-playbook  { border-left: 3px solid #4f46e5; background:#e0e7ff; padding:4px 10px; border-radius:4px; margin:2px 0; font-size:12px; font-family:'JetBrains Mono',monospace; }
.msg-threat-intel  { border-left: 3px solid #ea580c; background:#ffedd5; padding:4px 10px; border-radius:4px; margin:2px 0; font-size:12px; font-family:'JetBrains Mono',monospace; }
.msg-action-exec   { border-left: 3px solid #16a34a; background:#f0fdf4; padding:4px 10px; border-radius:4px; margin:2px 0; font-size:12px; font-family:'JetBrains Mono',monospace; }
.msg-gemini        { border-left: 3px solid #d97706; background:#fef3c7; padding:4px 10px; border-radius:4px; margin:2px 0; font-size:12px; font-family:'JetBrains Mono',monospace; }

/* MITRE badges */
.mitre-badge { display:inline-block; background:#e0e7ff; color:#3730a3; border:1px solid #c7d2fe; padding:2px 6px; border-radius:4px; font-size:10px; font-weight:600; margin:2px; font-family:'JetBrains Mono',monospace; }

/* Confidence bar */
/* Confidence bar */
.conf-bar-container { background:#1e293b; border-radius:6px; height:12px; width:100%; margin:8px 0; overflow:hidden; border:1px solid #334155; }
.conf-bar-fill { height:100%; border-radius:6px; transition:width 1s cubic-bezier(0.4, 0, 0.2, 1); background:linear-gradient(90deg, #3b82f6, #60a5fa); box-shadow: 0 0 10px rgba(96, 165, 250, 0.3); }

/* Step progress */
.step-done    { color:#10b981; font-weight:600; }
.step-running { color:#3b82f6; font-weight:700; animation: pulse 2s infinite; }
.step-pending { color:#475569; }

/* Animations */
@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
@keyframes pulse { 0% { opacity: 1; transform: scale(1); } 50% { opacity: 0.7; transform: scale(1.05); } 100% { opacity: 1; transform: scale(1); } }
.spinning { display: inline-block; animation: spin 2s linear infinite; }

/* Metrics Ribbon */
.metrics-container { display: flex; justify-content: space-between; gap: 12px; margin-bottom: 24px; }
.metric-card { flex: 1; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 12px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.metric-label { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; font-weight: 600; }
.metric-value { font-size: 20px; font-weight: 800; color: #0f172a; }
.metric-delta { font-size: 10px; color: #10b981; margin-top: 2px; font-weight: 500; }

/* Dashboard Components */
.secops-card { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 16px; margin-bottom: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
.secops-card-header { font-size: 11px; font-weight: 600; letter-spacing: 1.5px; color: #2563eb; text-transform: uppercase; margin-bottom: 6px; }

.badge-critical { background:#fef2f2; color:#b91c1c; border:1px solid #f87171; padding:2px 8px; border-radius:12px; font-size:11px; font-weight:700; }
.badge-high     { background:#fff7ed; color:#c2410c; border:1px solid #fb923c; padding:2px 8px; border-radius:12px; font-size:11px; font-weight:700; }
.badge-medium   { background:#fefce8; color:#a16207; border:1px solid #facc15; padding:2px 8px; border-radius:12px; font-size:11px; font-weight:700; }
.badge-low      { background:#f0fdf4; color:#15803d; border:1px solid #4ade80; padding:2px 8px; border-radius:12px; font-size:11px; font-weight:700; }

.hitl-panel { background:#ffffff; border:2px solid #3b82f6; border-radius:8px; padding:16px; text-align:center; box-shadow: 0 4px 12px rgba(59,130,246,0.15); }
.hitl-title { font-size:16px; font-weight:700; color:#1d4ed8; margin-bottom:6px; }
.hitl-subtitle { font-size:12px; color:#64748b; margin-bottom:12px; }

.snow-card { background:#f0fdf4; border:1px solid #22c55e; border-radius:8px; padding:16px; }
.snow-resolved { color:#16a34a; font-size:18px; font-weight:800; }
.snow-field { color:#64748b; font-size:10px; text-transform:uppercase; letter-spacing:0.5px; }
.snow-value { color:#0f172a; font-size:12px; font-weight:500; margin-bottom:6px; }

.msg-orchestrator { border-left: 3px solid #0284c7; background:#f0f9ff; padding:4px 10px; border-radius:4px; margin:2px 0; font-size:12px; font-family:'JetBrains Mono',monospace; }
.msg-case-retrieval{ border-left: 3px solid #16a34a; background:#f0fdf4; padding:4px 10px; border-radius:4px; margin:2px 0; font-size:12px; font-family:'JetBrains Mono',monospace; }
.msg-rag-playbook  { border-left: 3px solid #4f46e5; background:#e0e7ff; padding:4px 10px; border-radius:4px; margin:2px 0; font-size:12px; font-family:'JetBrains Mono',monospace; }
.msg-threat-intel  { border-left: 3px solid #ea580c; background:#ffedd5; padding:4px 10px; border-radius:4px; margin:2px 0; font-size:12px; font-family:'JetBrains Mono',monospace; }
.msg-action-exec   { border-left: 3px solid #16a34a; background:#f0fdf4; padding:4px 10px; border-radius:4px; margin:2px 0; font-size:12px; font-family:'JetBrains Mono',monospace; }
.msg-gemini        { border-left: 3px solid #d97706; background:#fef3c7; padding:4px 10px; border-radius:4px; margin:2px 0; font-size:12px; font-family:'JetBrains Mono',monospace; }

.action-line-success { color:#15803d; font-family:'JetBrains Mono',monospace; font-size:11px; padding:2px 0; }
.action-line-queued  { color:#b45309; font-family:'JetBrains Mono',monospace; font-size:11px; padding:2px 0; }
.action-line-running { color:#1d4ed8; font-family:'JetBrains Mono',monospace; font-size:11px; padding:2px 0; }

.rep-danger { color:#dc2626; font-weight:700; background:#fee2e2; padding:1px 4px; border-radius:4px; }
.rep-warn   { color:#d97706; font-weight:700; background:#fef3c7; padding:1px 4px; border-radius:4px; }
.rep-clean  { color:#16a34a; font-weight:700; background:#dcfce7; padding:1px 4px; border-radius:4px; }

</style>
""", unsafe_allow_html=True)

# ── Constants ──────────────────────────────────────────────────────────────────
CASES = {
    "CASE-001": {
        "label": "🔴 CASE-001 · CRITICAL — Lateral Movement (Domain Admin)",
        "severity": "CRITICAL",
        "badge": "badge-critical",
        "desc": "Compromised domain admin account accessing 14 workstations sequentially at 02:14 UTC",
        "ts": "2026-03-20T02:14:33Z",
        "alerts": 3,
    },
    "CASE-002": {
        "label": "🟠 CASE-002 · HIGH — DNS Tunnelling C2 Exfiltration",
        "severity": "HIGH",
        "badge": "badge-high",
        "desc": "4.2 GB outbound DNS tunnelling to C2 domain registered 48h prior",
        "ts": "2026-03-20T11:43:17Z",
        "alerts": 3,
    },
    "CASE-003": {
        "label": "🟠 CASE-003 · HIGH — Ransomware Precursor (Cobalt Strike)",
        "severity": "HIGH",
        "badge": "badge-high",
        "desc": "PowerShell encoded execution + Cobalt Strike beacon on 3 dev endpoints",
        "ts": "2026-03-20T22:08:55Z",
        "alerts": 4,
    },
    "CASE-004": {
        "label": "🔴 CASE-004 · CRITICAL — DNS Tunneling (Data Exfil)",
        "severity": "CRITICAL",
        "badge": "badge-critical",
        "desc": "1.8 GB DNS TXT tunneling to research-sync-service.top from WKS-RES-042",
        "ts": "2026-03-22T10:15:00Z",
        "alerts": 2,
    },
    "CASE-005": {
        "label": "🟡 CASE-005 · MEDIUM — Suspicious Login (Tor/Russia)",
        "severity": "MEDIUM",
        "badge": "badge-medium",
        "desc": "Successful login from Tor exit node (185.220.101.52) involving MFA fatigue",
        "ts": "2026-03-24T05:22:11Z",
        "alerts": 2,
    },
    "CASE-006": {
        "label": "🔵 CASE-006 · LOW — DLP PII Leakage (Logs)",
        "severity": "LOW",
        "badge": "badge-low",
        "desc": "SSN and Credit Card numbers detected in cleartext in Checkout-API logs",
        "ts": "2026-03-24T11:45:00Z",
        "alerts": 1,
    },
    "CASE-007": {
        "label": "🔴 CASE-007 · HIGH — Potential DNS Exfiltration Activity",
        "severity": "HIGH",
        "badge": "badge-high",
        "desc": "Suspicious PowerShell command making DNS TXT requests to mediareleaseupdates.com from WIN10-8YB72USR (User: JDOE)",
        "ts": "2026-03-24T10:34:22Z",
        "alerts": 1,
    },
    "CASE-008": {
        "label": "🔴 CASE-008 · CRITICAL — Brute Force + Suspicious CertUtil",
        "severity": "CRITICAL",
        "badge": "badge-critical",
        "desc": "Multi-stage attack targeting WIN10-8YB72USR; brute force leading to malware execution via certutil",
        "ts": "2026-03-24T12:51:19Z",
        "alerts": 2,
    },
    "CASE-009": {
        "label": "🔵 CASE-009 · LOW — Insecure TLS (Policy Violation)",
        "severity": "LOW",
        "badge": "badge-low",
        "desc": "Internal Dev server negotiating deprecated TLS 1.0/1.1 protocols",
        "ts": "2026-03-25T14:30:00Z",
        "alerts": 1,
    },
}

PIPELINE_STEPS = [
    "Case Ingestion",
    "Data Retrieval",
    "Playbook RAG",
    "Threat Intel",
    "Case Synthesis & Reporting",
    "Recommendation",
    "HITL Approval",
    "Action Execution",
    "Case Closure"
]

ALL_PLAYBOOKS = [
    ("PB-003", "Credential Compromise Response"),
    ("PB-007", "C2 Containment & Forensics"),
    ("PB-012", "Ransomware Isolation Protocol"),
    ("PB-019", "Phishing Response"),
    ("PB-024", "Insider Threat Investigation"),
    ("PB-042", "DNS Tunneling & Data Exfiltration Response"),
    ("PB-043", "Ransomware Staging & Tooling Defense"),
]

AGENT_COLORS = {
    "ORCHESTRATOR":    ("#2E5FA3", "msg-orchestrator"),
    "CASE-RETRIEVAL":  ("#0F6E56", "msg-case-retrieval"),
    "RAG-PLAYBOOK":    ("#534AB7", "msg-rag-playbook"),
    "THREAT-INTEL":    ("#B45309", "msg-threat-intel"),
    "ACTION-EXEC":     ("#16A34A", "msg-action-exec"),
    "GEMINI":          ("#D97706", "msg-gemini"),
}

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")

def _severity_badge(sev: str) -> str:
    cls = {"CRITICAL": "badge-critical", "HIGH": "badge-high", "MEDIUM": "badge-medium", "LOW": "badge-low"}.get(sev.upper(), "badge-low")
    return f'<span class="{cls}">{sev}</span>'

def _rep_color(score: int) -> str:
    if score >= 70: return "rep-danger"
    if score >= 40: return "rep-warn"
    return "rep-clean"

def _conf_bar(score: float) -> str:
    # Ensure score is between 0 and 1
    s = max(0, min(1, float(score)))
    pct = int(s * 100)
    color = "#10b981" if pct >= 80 else ("#f59e0b" if pct >= 60 else "#ef4444")
    return f"""
    <div style="margin-top:8px">
      <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
        <span style="color:#94a3b8;font-weight:600">AI Confidence</span>
        <span style="color:{color};font-weight:700">{pct}%</span>
      </div>
      <div class="conf-bar-container">
        <div class="conf-bar-fill" style="width:{pct}%"></div>
      </div>
    </div>"""

# ── Session state initialisation ───────────────────────────────────────────────
def _init_state():
    defaults = {
        "selected_case": "CASE-001",
        "pipeline_step": 0,       # 0 = not started
        "case_data": None,
        "rag_results": None,
        "ioc_data": None,
        "analysis": None,
        "execution": None,
        "closure": None,
        "agent_log": [],
        "audit_trail": [],
        "hitl_state": "none",     # none | awaiting | override | reject | approved
        "hitl_decision": None,
        "override_playbook": None,
        "analyst_feedback": None,
        "analyst_name": "j.analyst@bank.com",
        "error": None,
        "running": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()

# ── Helper: log agent message ──────────────────────────────────────────────────
def _log(agent: str, message: str):
    st.session_state["agent_log"].append({
        "ts": _now(), "agent": agent, "message": message
    })

def _audit(actor: str, action: str, outcome: str):
    st.session_state["audit_trail"].append({
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "actor": actor, "action": action, "outcome": outcome,
    })

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ Agentic SecOps")
    st.markdown('<p style="color:#4a9eff;font-size:11px;letter-spacing:1px;text-transform:uppercase;margin-top:-8px">SOC AIOps Platform · POC</p>', unsafe_allow_html=True)
    st.divider()

    st.markdown("### Select Case")
    case_options = list(CASES.keys())
    selected = st.selectbox(
        "Case",
        case_options,
        format_func=lambda x: CASES[x]["label"],
        index=case_options.index(st.session_state["selected_case"]),
        label_visibility="collapsed",
    )
    if selected != st.session_state["selected_case"]:
        # Reset state on case change
        for k in ["pipeline_step","case_data","rag_results","ioc_data","analysis","execution","closure",
                  "agent_log","audit_trail","hitl_state","hitl_decision","override_playbook",
                  "analyst_feedback","error","running"]:
            st.session_state[k] = None if k not in ["pipeline_step","agent_log","audit_trail","hitl_state"] else (0 if k=="pipeline_step" else ([] if k in ["agent_log","audit_trail"] else "none"))
        st.session_state["selected_case"] = selected

    case_id = st.session_state["selected_case"]
    meta = CASES[case_id]

    st.markdown("### 🎛️ Operations")
    run_btn = st.button(
        "▶ Run Analysis" if st.session_state["pipeline_step"] == 0 else "🔄 Reset & Re-run",
        type="primary", use_container_width=True,
        disabled=bool(st.session_state.get("running")),
    )
    if run_btn:
        for k in ["pipeline_step","case_data","rag_results","ioc_data","analysis","execution","closure",
                  "agent_log","audit_trail","hitl_state","hitl_decision","override_playbook",
                  "analyst_feedback","error","running"]:
            if k == "pipeline_step": st.session_state[k] = 0
            elif k in ["agent_log","audit_trail"]: st.session_state[k] = []
            elif k == "hitl_state": st.session_state[k] = "none"
            elif k in ["analysis","case_data","execution","closure"]: st.session_state[k] = {}
            elif k == "running": st.session_state[k] = False
            else: st.session_state[k] = None
        st.session_state["running"] = True
        st.rerun()

    st.markdown("### Analyst")
    st.session_state["analyst_name"] = st.text_input(
        "Analyst ID", value=st.session_state["analyst_name"], label_visibility="collapsed"
    )

    st.divider()

    st.markdown(f"""
    <div class="secops-card" style="margin-top:8px">
      <div class="secops-card-header">Case Details</div>
      <div style="margin-bottom:6px">{_severity_badge(meta['severity'])}</div>
      <div style="font-size:12px;color:#0f172a;margin-bottom:6px">{meta['desc']}</div>
      <div style="font-size:11px;color:#64748b">🕐 {meta['ts'][:16].replace('T',' ')} UTC</div>
      <div style="font-size:11px;color:#64748b">🔔 {meta['alerts']} alerts correlated</div>
    </div>
    """, unsafe_allow_html=True)

if "active_steps" not in st.session_state:
    st.session_state["active_steps"] = set()

if "session_service" not in st.session_state:
    from google.adk.sessions import InMemorySessionService
    st.session_state["session_service"] = InMemorySessionService()

# Main area top: progress bar
st.markdown("# 🛡️ Agentic SecOps")
st.markdown(f'<p style="color:#64748b;margin-top:-14px">Agentic AIOps · Security Operations Centre · {case_id}</p>', unsafe_allow_html=True)

# Metrics Ribbon
# ... (omitted for brevity in replace tool, but it's there)
# (Actually, I need to make sure I don't delete the metrics ribbon. 
# I'll use multiple chunks or a more precise range)

# Check line 355 for the start of the progress area

# Metrics Ribbon
active_criticals = sum(1 for c in CASES.values() if c["severity"] == "CRITICAL")
avg_containment = "2m 14s"
auto_remed_pct = 92 if st.session_state["pipeline_step"] >= 9 else 84

st.markdown(f"""
<div class="metrics-container">
  <div class="metric-card">
    <div class="metric-label">Avg. Containment</div>
    <div class="metric-value">{avg_containment}</div>
    <div class="metric-delta">↑ 12% vs last week</div>
  </div>
  <div class="metric-card">
    <div class="metric-label">Active Criticals</div>
    <div class="metric-value">{active_criticals:02d}</div>
    <div class="metric-delta" style="color:#ef4444">High Alert</div>
  </div>
  <div class="metric-card">
    <div class="metric-label">Auto-Remediation</div>
    <div class="metric-value">{auto_remed_pct}%</div>
    <div class="metric-delta">Target: 90%</div>
  </div>
</div>
""", unsafe_allow_html=True)

step = st.session_state.get("pipeline_step", 0)

cols = st.columns(9)
for i, (col, name) in enumerate(zip(cols, PIPELINE_STEPS)):
    step_num = i + 1
    if step > step_num:
        icon, cls = "✓", "step-done"
    elif step == step_num or step_num in st.session_state.get("active_steps", set()):
        icon, cls = '<span class="spinning">⟳</span>', "step-running"
    else:
        icon, cls = "○", "step-pending"
    col.markdown(f'<div style="text-align:center"><span class="{cls}" style="font-size:18px">{icon}</span><br><span style="font-size:9px;color:#64748b">{step_num}. {name}</span></div>', unsafe_allow_html=True)

st.divider()

# ── Two-column layout: main + agent log ────────────────────────────────────────
main_col, log_col = st.columns([3, 1])

# ── AGENT LOG (right sidebar panel) ────────────────────────────────────────────
with log_col:
    st.markdown("### 📡 Agent Log")
    log_container = st.container(height=650)
    with log_container:
        logs = st.session_state.get("agent_log", [])
        if not logs:
            st.markdown('<div style="color:#374151;font-size:12px;font-family:monospace">Waiting for pipeline...</div>', unsafe_allow_html=True)
        for entry in logs:
            agent = entry["agent"]
            _, css_class = AGENT_COLORS.get(agent, ("#888", "msg-orchestrator"))
            st.markdown(
                f'<div class="{css_class}"><span style="color:#64748b">{entry["ts"]}</span> '
                f'<strong>{agent}</strong><br>{entry["message"]}</div>',
                unsafe_allow_html=True
            )

# ── MAIN CONTENT ───────────────────────────────────────────────────────────────
with main_col:

    # ── Run pipeline if triggered ──────────────────────────────────────────────
    if st.session_state.get("running") and st.session_state["pipeline_step"] == 0:
        try:
            import asyncio
            import sys
            sys.path.insert(0, str(Path(__file__).parent))
            from runner import run_adk_pipeline
            
            # Generate a fresh ADK session ID
            session_id = f"session-{case_id}-{int(time.time())}"
            st.session_state["adk_session_id"] = session_id

            async def run_pipeline_to_hitl():
                with st.status(f"🛠️ Orchestrator: Starting Pipeline for {case_id}...", expanded=True) as status:
                    _audit("SecOps Orchestrator (AI)", f"Pipeline started for {case_id}", "Initiated")
                    async for event in run_adk_pipeline(case_id, session_id, st.session_state["analyst_name"], st.session_state["session_service"]):
                        if event["type"] == "step":
                            st.session_state["pipeline_step"] = event["step"]
                            if event["step"] == 2: status.update(label="🔍 EnrichmentAgent: Gathering Intelligence (Steps 2-4)...", state="running")
                            elif event["step"] == 3: status.update(label="🔍 EnrichmentAgent: Querying RAG Playbooks...", state="running")
                            elif event["step"] == 4: status.update(label="🔍 EnrichmentAgent: Enriching Threat Intel...", state="running")
                            elif event["step"] == 5: status.update(label="🧠 ThreatAnalystAgent: Synthesizing Threat Report (Step 5)...", state="running")
                            elif event["step"] == 6: status.update(label="✅ Recommendation Ready", state="complete")
                        elif event["type"] == "active_steps":
                            st.session_state["active_steps"] = event["steps"]
                        elif event["type"] == "active_step_add":
                            st.session_state["active_steps"].add(event["step"])
                        elif event["type"] == "active_step_remove":
                            st.session_state["active_steps"].discard(event["step"])
                        elif event["type"] == "log":
                            _log(event["agent"], event["message"])
                            st.write(f"**{event['agent']}**: {event['message']}")
                        elif event["type"] == "state":
                            st.session_state[event["key"]] = event["data"]
                        elif event["type"] == "hitl":
                            st.session_state["hitl_state"] = event["state"]
                            st.session_state["active_steps"] = set()
                            if event["state"] == "awaiting":
                                st.session_state["pipeline_step"] = 7
                                _audit("SecOps Orchestrator (AI)", "Pipeline paused for HITL approval", "AWAITING_ANALYST")
                            else:
                                # For auto_approved, we keep step at 6 or move to a transitioning state
                                # The auto_approved block below will jump it to 8.
                                pass 
                            break

            asyncio.run(run_pipeline_to_hitl())
            st.session_state["running"] = False
            st.rerun()

        except Exception as e:
            st.session_state["error"] = str(e)
            import traceback
            traceback.print_exc()
            st.session_state["running"] = False
            _log("ORCHESTRATOR", f"❌ ERROR: {e}")

    # ── Display error if any ───────────────────────────────────────────────────
    if st.session_state.get("error"):
        st.error(f"⚠️ Pipeline Error: {st.session_state['error']}")
        st.markdown("**Check your `.env` file has `GOOGLE_API_KEY`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION` set.**")

    # ── Step 2: Show case data ─────────────────────────────────────────────────
    if st.session_state["pipeline_step"] >= 2 and st.session_state.get("case_data"):
        cd = st.session_state["case_data"]
        raw = cd["raw_case"]

        with st.expander("📂 Step 2 — Data Retrieved from SecOps", expanded=False):
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Correlated Alerts**")
                for a in cd["alerts"]:
                    sev_color = "🔴" if a["severity"] == "CRITICAL" else "🟠"
                    st.markdown(f"{sev_color} `{a['alert_id']}` **{a['rule_name']}**  \n`{a['timestamp'][:16]}` · src: `{a['source_ip']}`")
            with c2:
                st.markdown("**Affected Assets**")
                for asset in cd["assets"]:
                    st.markdown(f"💻 **{asset['hostname']}** (`{asset['ip']}`)  \n{asset['os']} · `{asset['user']}`")

            st.markdown("**Raw CEF Log Sample**")
            log_lines = cd["logs"].strip().split("\n")[:6]
            st.code("\n".join(log_lines), language="text")

    # ── Step 3: RAG results ────────────────────────────────────────────────────
    if st.session_state["pipeline_step"] >= 3 and st.session_state.get("rag_results"):
        rags = st.session_state["rag_results"]
        with st.expander("📚 Step 3 — Playbook Matches (RAG)", expanded=False):
            for i, r in enumerate(rags):
                score_pct = int(r.get("relevance_score", 0) * 100)
                prefix = "🥇" if i == 0 else ("🥈" if i == 1 else "🥉")
                st.markdown(f"""
                <div class="secops-card">
                  <div style="display:flex;justify-content:space-between;align-items:center">
                    <span style="font-weight:700;color:#e2e8f0">{prefix} {r['playbook_id']} — {r['playbook_name']}</span>
                    <span style="font-size:20px;font-weight:800;color:{'#22c55e' if score_pct>=80 else '#f59e0b'}">{score_pct}%</span>
                  </div>
                  <div style="color:#94a3b8;font-size:12px;margin-top:8px;font-style:italic">"{r.get('excerpt','')}"</div>
                </div>
                """, unsafe_allow_html=True)

    # ── Step 4: IoC enrichments ────────────────────────────────────────────────
    if st.session_state["pipeline_step"] >= 4 and st.session_state.get("ioc_data"):
        ioc_data = st.session_state["ioc_data"]
        with st.expander("🔬 Step 4 — IoC Enrichments (Threat Intel)", expanded=False):
            all_iocs = (
                [(d, "ip") for d in ioc_data.get("ips", [])] +
                [(d, "hash") for d in ioc_data.get("hashes", [])] +
                [(d, "domain") for d in ioc_data.get("domains", [])]
            )
            for ioc, itype in all_iocs:
                indicator = ioc.get("ip") or ioc.get("hash") or ioc.get("domain") or "?"
                score = ioc.get("reputation_score", 0)
                verdict = ioc.get("verdict", "Unknown")
                mitre = ioc.get("mitre_techniques", [])
                rep_cls = _rep_color(score)
                mitre_html = " ".join(f'<span class="mitre-badge">{t}</span>' for t in mitre)
                st.markdown(f"""
                <div class="secops-card">
                  <div style="display:flex;justify-content:space-between;align-items:flex-start">
                    <div>
                      <span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:#60a5fa">{itype.upper()}</span>
                      <span style="font-weight:700;font-family:'JetBrains Mono',monospace;font-size:13px;color:#e2e8f0;margin-left:8px">{indicator[:60]}</span><br>
                      <span style="color:#94a3b8;font-size:12px">{ioc.get('classification','Unknown')}</span>
                    </div>
                    <div style="text-align:right">
                      <span class="{rep_cls}" style="font-size:22px">{score}</span>
                      <div style="font-size:10px;color:#64748b">rep. score</div>
                    </div>
                  </div>
                  <div style="margin-top:6px">
                    <span style="font-size:11px;color:#94a3b8">Family: {ioc.get('malware_family') or 'Unknown'} · Campaign: {ioc.get('campaign') or 'Unknown'} · Verdict: <strong style="color:{'#ef4444' if 'Malicious' in verdict else '#f59e0b' if 'Suspicious' in verdict else '#22c55e'}">{verdict}</strong></span>
                  </div>
                  <div style="margin-top:6px">{mitre_html}</div>
                </div>
                """, unsafe_allow_html=True)

    # ── Step 5/6: Gemini analysis card ────────────────────────────────────────
    if st.session_state["pipeline_step"] >= 6 and st.session_state.get("analysis"):
        analysis = st.session_state["analysis"]
        sev = analysis.get("severity", "HIGH")
        conf = analysis.get("confidence_score", 0)
        mitre = analysis.get("mitre_techniques", [])
        ioc_enrichments = analysis.get("ioc_enrichments", [])

        st.markdown("---")
        st.markdown("## 🧠 Step 5 — AI Threat Synthesis")

        # Main analysis card
        mitre_html = " ".join(
            f'<span class="mitre-badge" title="{t.get("technique_name","")} · {t.get("tactic","")}">{t.get("technique_id","")}</span>'
            for t in mitre
        )
        st.markdown(f"""
        <div class="secops-card">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
            <div style="flex:2;min-width:200px">
              <div class="secops-card-header">Threat Classification</div>
              <div style="font-size:18px;font-weight:700;color:#f1f5f9;margin-bottom:8px">{analysis.get('threat_classification','')}</div>
              <div style="margin-bottom:8px">{_severity_badge(sev)}</div>
              <p style="color:#94a3b8;font-size:13px;line-height:1.6">{analysis.get('case_summary','')}</p>
            </div>
            <div style="flex:1;min-width:160px;background:#0f172a;padding:16px;border-radius:12px;border:1px solid #1e293b">
              {_conf_bar(conf)}
              <div style="margin-top:20px;display:grid;grid-template-columns:1fr 1fr;gap:12px">
                <div>
                  <div class="secops-card-header" style="margin-bottom:2px">Endpoints</div>
                  <div style="font-size:24px;font-weight:800;color:#f97316">{analysis.get('blast_radius_endpoints',0)}</div>
                </div>
                <div>
                  <div class="secops-card-header" style="margin-bottom:2px">Users</div>
                  <div style="font-size:24px;font-weight:800;color:#f97316">{analysis.get('blast_radius_users',0)}</div>
                </div>
              </div>
            </div>
          </div>
          <div style="margin-top:20px">
            <div class="secops-card-header">MITRE ATT&CK Techniques</div>
            {mitre_html if mitre_html else '<span style="color:#64748b;font-size:12px">None identified</span>'}
          </div>
          <div style="margin-top:16px;padding:12px;background:#0a1628;border-radius:8px;border-left:3px solid #2563eb">
            <div class="secops-card-header">Recommended Playbook</div>
            <div style="font-weight:700;color:#60a5fa;font-size:14px">
              {analysis.get('recommended_playbook_id','')} — {analysis.get('recommended_playbook_name','')}
            </div>
            <div style="color:#94a3b8;font-size:12px;margin-top:4px">{analysis.get('playbook_rationale','')}</div>
            <div style="color:#64748b;font-size:11px;margin-top:4px">⏱ Est. containment: {analysis.get('estimated_containment_time_minutes',0)} min</div>
          </div>
          <div style="margin-top:12px">
            <div class="secops-card-header">Required Analyst Actions</div>
            {''.join(f'<div style="color:#e2e8f0;font-size:12px;padding:2px 0">▸ {a}</div>' for a in analysis.get('analyst_actions_required',[]))}
          </div>
        </div>
        """, unsafe_allow_html=True)

    # ── Step 7: HITL Panel ─────────────────────────────────────────────────────
    if st.session_state["pipeline_step"] >= 6 and st.session_state["hitl_state"] != "none":
        hitl = st.session_state["hitl_state"]
        analysis = st.session_state.get("analysis", {})

        if hitl == "auto_approved":
            st.session_state["hitl_state"] = "approved"
            st.session_state["hitl_decision"] = "Auto-Approved"
            _log("ORCHESTRATOR", "Agent recommended auto-approval. Proceeding to execution.")
            _audit(st.session_state["analyst_name"], f"HITL: Auto-Approved {analysis.get('recommended_playbook_id')}", "Auto-Approved")
            from sentinel.tools.snow_mcp import add_worknote
            raw = st.session_state["case_data"]["raw_case"]
            snow_ref = raw.get("snow_incident_ref", "INC0000000")
            add_worknote(snow_ref, f"HITL DECISION: Auto-approved by system rules at {datetime.now(timezone.utc).isoformat()}", author="SYSTEM")
            st.session_state["pipeline_step"] = 8
            st.session_state["running"] = True
            st.rerun()

        if hitl == "awaiting":
            st.markdown("---")
            st.markdown(f"""
            <div class="hitl-panel">
              <div class="hitl-title">⏸ Human-in-the-Loop Approval Required</div>
              <div class="hitl-subtitle">Review the Gemini analysis above, then choose an action to proceed.</div>
            </div>
            """, unsafe_allow_html=True)

            col_a, col_o, col_r = st.columns(3)
            with col_a:
                if st.button("✅ Accept Recommendation", type="primary", use_container_width=True):
                    st.session_state["hitl_state"] = "approved"
                    st.session_state["hitl_decision"] = "Accepted"
                    _log("ORCHESTRATOR", f"HITL: Accepted by {st.session_state['analyst_name']}")
                    _audit(st.session_state["analyst_name"], f"HITL: Accepted {analysis.get('recommended_playbook_id')}", "Approved")
                    from sentinel.tools.snow_mcp import add_worknote
                    raw = st.session_state["case_data"]["raw_case"]
                    snow_ref = raw.get("snow_incident_ref", "INC0000000")
                    add_worknote(snow_ref, f"HITL DECISION: Accepted by {st.session_state['analyst_name']} at {datetime.now(timezone.utc).isoformat()}", author=st.session_state["analyst_name"])
                    st.session_state["pipeline_step"] = 8
                    st.session_state["running"] = True
                    st.rerun()
            with col_o:
                if st.button("🔄 Override Playbook", use_container_width=True):
                    st.session_state["hitl_state"] = "override"
                    st.rerun()
            with col_r:
                if st.button("❌ Reject & Revise", use_container_width=True):
                    st.session_state["hitl_state"] = "reject"
                    st.rerun()

        elif hitl == "override":
            st.markdown("---")
            st.markdown('<div class="secops-card"><div class="hitl-title" style="text-align:left">🔄 Override — Select Alternative Playbook</div>', unsafe_allow_html=True)

            pb_options = {pid: f"{pid} — {pname}" for pid, pname in ALL_PLAYBOOKS}
            selected_pb = st.selectbox(
                "Select alternative playbook",
                list(pb_options.keys()),
                format_func=lambda x: pb_options[x],
                index=0,
            )
            override_reason = st.text_area("Reason for override (optional)", placeholder="e.g. C2 containment is higher priority than credential reset given active exfil...", height=80)

            col1, col2 = st.columns(2)
            with col1:
                if st.button("✅ Confirm Override", type="primary", use_container_width=True):
                    _log("ORCHESTRATOR", f"HITL: Override — analyst selected {selected_pb}")
                    _audit(st.session_state["analyst_name"], f"HITL: Override → {selected_pb}", override_reason or "No reason given")
                    from sentinel.tools.snow_mcp import add_worknote
                    raw = st.session_state["case_data"]["raw_case"]
                    snow_ref = raw.get("snow_incident_ref","INC0000000")
                    add_worknote(snow_ref, f"HITL OVERRIDE by {st.session_state['analyst_name']}: {selected_pb} selected. Reason: {override_reason or 'None given'}", author=st.session_state["analyst_name"])
                    
                    st.session_state["override_playbook"] = selected_pb
                    st.session_state["hitl_decision"] = "override"
                    st.session_state["pipeline_step"] = 8
                    st.session_state["running"] = True
                    st.rerun()
            with col2:
                if st.button("← Back", use_container_width=True):
                    st.session_state["hitl_state"] = "awaiting"
                    st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

        elif hitl == "reject":
            st.markdown("---")
            st.markdown('<div class="secops-card"><div class="hitl-title" style="text-align:left">❌ Reject & Revise — Provide Analyst Feedback</div>', unsafe_allow_html=True)

            feedback = st.text_area(
                "Describe what the AI missed or should reconsider:",
                placeholder="e.g. The ransomware isolation protocol should take priority. The blast radius likely extends beyond dev workstations — check for shared file server access...",
                height=120,
            )
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔁 Submit Feedback & Re-analyse", type="primary", use_container_width=True, disabled=not feedback):
                    _log("ORCHESTRATOR", f"HITL: Rejected — feedback submitted by {st.session_state['analyst_name']}")
                    _audit(st.session_state["analyst_name"], "HITL: Rejected — feedback submitted", feedback)
                    from sentinel.tools.snow_mcp import add_worknote
                    raw = st.session_state["case_data"]["raw_case"]
                    snow_ref = raw.get("snow_incident_ref","INC0000000")
                    add_worknote(snow_ref, f"HITL REJECT by {st.session_state['analyst_name']}: {feedback}", author=st.session_state["analyst_name"])
                    
                    st.session_state["analyst_feedback"] = feedback
                    st.session_state["hitl_decision"] = "reject"
                    st.session_state["pipeline_step"] = 8
                    st.session_state["running"] = True
                    st.rerun()
            with col2:
                if st.button("← Back", use_container_width=True):
                    st.session_state["hitl_state"] = "awaiting"
                    st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

    # ── Step 8: Action Execution ───────────────────────────────────────────────
    if st.session_state.get("running") and st.session_state["pipeline_step"] == 8:
        try:
            import asyncio
            from runner import resume_adk_pipeline
            
            session_id = st.session_state.get("adk_session_id", f"session-{case_id}")
            analyst = st.session_state["analyst_name"]
            decision = st.session_state["hitl_decision"]
            override = st.session_state.get("override_playbook")
            feedback = st.session_state.get("analyst_feedback")
            analysis = st.session_state["analysis"]

            async def run_resume_pipeline():
                with st.status("⚡ ActionExecutor: Implementing Remediation (Step 8)...", expanded=True) as status:
                    async for event in resume_adk_pipeline(session_id, analyst, decision, analysis, case_id, st.session_state["session_service"], override, feedback):
                        if event["type"] == "log":
                            _log(event["agent"], event["message"])
                            st.write(f"**{event['agent']}**: {event['message']}")
                        elif event["type"] == "state":
                            st.session_state[event["key"]] = event["data"]
                        elif event["type"] == "step":
                            st.session_state["pipeline_step"] = event["step"]
                        elif event["type"] == "hitl":
                            st.session_state["hitl_state"] = event["state"]
                            break
                        elif event["type"] == "finish":
                            st.session_state["pipeline_step"] = 10

            asyncio.run(run_resume_pipeline())
            st.session_state["running"] = False
            if st.session_state.get("pipeline_step") == 10:
                _audit("SecOps Orchestrator (AI)", "Pipeline complete", "RESOLVED")
            st.rerun()

        except Exception as e:
            st.session_state["error"] = str(e)
            import traceback
            traceback.print_exc()
            st.session_state["running"] = False
            _log("ORCHESTRATOR", f"❌ ERROR in action execution: {e}")

    # ── Step 8 display: action execution log ───────────────────────────────────
    if st.session_state["pipeline_step"] >= 9 and st.session_state.get("execution"):
        exec_data = st.session_state["execution"]
        steps = exec_data["execution"].get("action_steps", [])
        playbook_id = st.session_state["analysis"].get("recommended_playbook_id","")
        playbook_name = st.session_state["analysis"].get("recommended_playbook_name","")

        with st.expander(f"⚙️ Step 8 — Action Execution Details", expanded=False):
            st.markdown(f'<div style="color:#60a5fa;font-size:13px;font-weight:600">{playbook_id} — {playbook_name}</div>', unsafe_allow_html=True)
            action_container = st.container()
            with action_container:
                for s in steps:
                    status = s.get("status","")
                    icon = "✅" if status == "success" else ("⏳" if status == "queued" else ("🔄" if status == "in_progress" else "❌"))
                    color_cls = "action-line-success" if status == "success" else ("action-line-queued" if status in ("queued","in_progress") else "action-line-running")
                    st.markdown(
                        f'<div class="{color_cls}">{icon} Step {s["step"]}: {s["action"]} '
                        f'<span style="color:#475569">· {s["target"]} · {s["duration_seconds"]}s · <strong>{status.upper()}</strong></span></div>',
                        unsafe_allow_html=True
                    )

    # ── Step 9: SNOW ticket card + audit trail ─────────────────────────────────
    if st.session_state["pipeline_step"] >= 10 and st.session_state.get("closure"):
        closure = st.session_state["closure"]
        snow_state = closure.get("snow_state", {})
        analysis = st.session_state.get("analysis", {})

        with st.expander("📋 Step 9 — Case Closure & Audit Details", expanded=False):
            # SNOW ticket card
            opened_at = snow_state.get("opened_at","—")[:16].replace("T"," ") if snow_state.get("opened_at") else "—"
            resolved_at = snow_state.get("resolved_at","—")
            sla_str = "✅ Resolved within SLA"

        st.markdown(f"""
        <div class="snow-card">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
            <div>
              <div class="secops-card-header">ServiceNow Incident</div>
              <div class="snow-resolved">🟢 {closure['snow_ref']}</div>
              <div style="font-size:12px;color:#22c55e;margin-top:2px">{sla_str}</div>
            </div>
            <div style="text-align:right">
              <span style="background:#14532d;color:#86efac;padding:4px 14px;border-radius:20px;font-size:12px;font-weight:700">RESOLVED</span>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-top:16px;flex-wrap:wrap">
            <div><div class="snow-field">Priority</div><div class="snow-value">{snow_state.get('priority','—')}</div></div>
            <div><div class="snow-field">Opened</div><div class="snow-value">{opened_at} UTC</div></div>
            <div><div class="snow-field">Category</div><div class="snow-value">Security — {snow_state.get('subcategory','Cyber Incident')}</div></div>
            <div><div class="snow-field">Threat Class</div><div class="snow-value">{analysis.get('threat_classification','—')}</div></div>
            <div><div class="snow-field">HITL Decision</div><div class="snow-value">{st.session_state.get('hitl_decision','Accepted')}</div></div>
            <div><div class="snow-field">Assigned</div><div class="snow-value" style="font-size:11px">SecOps AI + {st.session_state.get('analyst_name','')}</div></div>
          </div>
          <div style="margin-top:12px">
            <div class="snow-field">Resolution Notes Preview</div>
            <div style="background:#0a1a0a;border-radius:6px;padding:10px;margin-top:4px;font-family:'JetBrains Mono',monospace;font-size:11px;color:#94a3b8;white-space:pre-wrap">{closure['close_notes'][:600]}...</div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        # Audit trail table
        st.markdown("### 📊 Full Audit Trail")
        audit = st.session_state.get("audit_trail", [])
        if audit:
            st.markdown("""
            <style>
            .audit-table { width:100%; border-collapse:collapse; font-size:12px; }
            .audit-table th { background:#0f172a; color:#4a9eff; padding:8px; text-align:left; border-bottom:1px solid #1e3a5f; }
            .audit-table td { padding:8px; border-bottom:1px solid #1e2a3a; color:#94a3b8; }
            .audit-table tr:hover td { background:#0a1628; }
            </style>
            """, unsafe_allow_html=True)
            rows = "".join(
                f"<tr><td style='font-family:monospace;color:#60a5fa'>{e['timestamp']}</td><td style='color:#e2e8f0'>{e['actor']}</td><td>{e['action']}</td><td style='color:#22c55e'>{e['outcome']}</td></tr>"
                for e in audit
            )
            st.markdown(f'<table class="audit-table"><thead><tr><th>Timestamp</th><th>Actor</th><th>Action</th><th>Outcome</th></tr></thead><tbody>{rows}</tbody></table>', unsafe_allow_html=True)

        st.markdown(f"""
        <div style="text-align:center;margin-top:24px;padding:16px;background:linear-gradient(135deg,#0a1f0a,#051505);border-radius:12px;border:1px solid #16a34a">
          <div style="font-size:28px">🛡️ ✅</div>
          <div style="font-size:16px;font-weight:700;color:#22c55e;margin:4px 0">Case Resolved — Agentic SecOps</div>
          <div style="font-size:12px;color:#64748b">Full audit trail written to ServiceNow · {analysis.get('estimated_containment_time_minutes',0)} min containment</div>
        </div>
        """, unsafe_allow_html=True)

    # ── Welcome screen (pipeline not started) ─────────────────────────────────
    if st.session_state["pipeline_step"] == 0:
        st.markdown("""
        <div style="text-align:center;padding:60px 40px">
          <div style="font-size:72px;margin-bottom:16px">🛡️</div>
          <h2 style="color:#e2e8f0;font-weight:800">Agentic SecOps</h2>
          <p style="color:#64748b;font-size:15px;max-width:500px;margin:0 auto 24px">
            Next-generation agentic AIOps for the Security Operations Centre.<br>
            Select a case from the sidebar and click <strong style="color:#4a9eff">Run Analysis</strong> to begin.
          </p>
          <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;max-width:600px;margin:0 auto">
            <div class="secops-card" style="text-align:center">
              <div style="font-size:28px">🤖</div>
              <div style="font-size:12px;color:#94a3b8;margin-top:8px">5 specialist AI agents collaborating in real time</div>
            </div>
            <div class="secops-card" style="text-align:center">
              <div style="font-size:28px">📚</div>
              <div style="font-size:12px;color:#94a3b8;margin-top:8px">RAG-powered dynamic playbook selection</div>
            </div>
            <div class="secops-card" style="text-align:center">
              <div style="font-size:28px">✋</div>
              <div style="font-size:12px;color:#94a3b8;margin-top:8px">Human-in-the-loop approval with full audit trail</div>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)
