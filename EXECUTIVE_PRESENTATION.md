# 🛡️ Agentic SecOps: Executive Solution Overview
**Agentic AIOps Platform · Powered by Gemini 2.0 & Google ADK**

---

## 🏗️ 1. Architecture: The Agentic Core
Agentic SecOps is built on a **Hybrid Agentic Architecture** that combines three core Google/Industry standards to automate the Security Operations Center (SOC).

```mermaid
graph TD
    A[Case Ingestion] --> B[SOCOrchestrator Agent]
    B -- "Delegate (Steps 2-4)" --> C[EnrichmentAgent]
    C -- "MCP Tool" --> D[(SecOps Data)]
    C -- "RAG Method" --> E[(Playbook Library)]
    C -- "MCP Tool" --> F[(Threat Intel)]
    B -- "Delegate (Step 5)" --> G[ThreatAnalystAgent]
    G -- "Synthesis" --> H[Structured Case Report]
    H -- "HITL Approval Gate" --> I[Decision Phase (Step 6)]
    I -- "Delegate (Steps 7-8)" --> J[ActionExecutorAgent]
    J -- "MCP Tool" --> K[(SOAR Remediation)]
    J -- "MCP Tool" --> L[(ServiceNow Closure)]
```

### Key Pillars:
- **Google ADK (Agent Development Kit)**: Orchestrates the hand-offs between specialized AI agents.
- **RAG (Retrieval-Augmented Generation)**: Grounding the AI's recommendations in your company's official security playbooks.
- **MCP (Model Context Protocol)**: Standardized way for agents to "talk" to your existing security tools (GTI, ServiceNow, SIEM).

---

## 🚀 2. The 8-Step Agentic Pipeline
We have optimized the traditional SOC workflow into a high-performance, parallelized 8-step process.
 
| Step | Phase | Agent In-Charge | Description |
| :--- | :--- | :--- | :--- |
| **1** | **Ingestion** | Orchestrator | Case is received from SIEM (e.g. Google SecOps). |
| **2** | **Data Enrichment** | Enrichment | **Parallel**: Fetching raw logs, user data, and affected assets via MCP. |
| **3** | **Playbook Selection** | Enrichment | **Parallel**: RAG-based search to find the correct SOC procedure. |
| **4** | **Threat Intel** | Enrichment | **Parallel**: Enriching IPs/Domains/Hashes via GTI (Google Threat Intel). |
| **5** | **Impact Synthesis** | Analysis | Gemini reasons across all data to generate the Case Analysis report. |
| **6** | **HITL Review** | Analyst Gate | Pauses for human review (unless **Auto-Remediation** policy matches). |
| **7** | **Agentic Remediation**| Action Executor | Performs remediation (e.g. blocking IPs) via SOAR & SNOW tools. |
| **8** | **Automated Closure** | Action Executor | Updates ServiceNow with full reports and resolves the SecOps case. |

---

## 🧪 3. Demo Walkthrough: CASE-001 (Lateral Movement)
*Demonstrating how the principles come together for a Critical Case.*

### 📂 Phase A: Detection & Parallel Enrichment (Steps 1-4)
- **Problem**: Compromised domain admin account accessing 14 workstations sequentially.
- **The Agentic Move**: Instead of 4 separate API calls, the `EnrichmentAgent` triggers one **Parallel Enrichment** turn.
  - **MCP (Data)**: Pulls logs showing the lateral movement originated from a phishing link.
  - **RAG (Knowledge)**: Matches the threat to **PB-003 (Credential Compromise Response)** with 92% relevance.
  - **MCP (Intel)**: Flags the attacker's C2 IP as "Malicious" via GTI.
 
### 🧠 Phase B: AI Threat Synthesis (Step 5)
- **Analysis**: Gemini reconciles the raw logs with the Intel and identifies the specific Domain Admin user (`j.smith`).
- **Blast Radius**: Identifies **14 machines** effectively communicating with the rogue domain.
- **Recommendation**: Gemini recommends execution of **PB-003**.

### ✅ Phase C: HITL & Execution (Steps 6-8)
- **Human Decision**: Because it's **CRITICAL**, the orchestrator pauses in Step 6. Analyst clicks "✅ Accept Recommendation."
- **ActionExecutor**: Resumes the pipeline in Step 7 and isolates host `WKS-RES-042` via EDR, suspends user `j.smith`, and blocks the IP at the firewall.

---

## 📈 4. Key Benefits for the Client
- **90% Latency Reduction**: No more waiting for agents to run sequentially. Steps 2, 3, and 4 happen at once in a single 'Parallel Enrichment' turn.
- **Model Agnostic**: UI and logic use the `ThreatAnalystAgent` persona, allowing you to swap models (Gemini, Vertex AI, etc.) without UI disruption.
- **Zero Re-Analysis Loops**: Direct handover from HITL to Execution ensures the agent never asks "Wait, what happened?" after you approve.
- **Auto-Remediation Policy**: Medium/Low cases with >90% AI confidence are processed autonomously, reducing MTTR to seconds for non-critical threats.

> [!TIP]
> **Production Readiness**: Every mock tool in this POC is built on the **Adapter Pattern**, meaning you can swap "Mocks" for "Production APIs" without rewriting any code.
