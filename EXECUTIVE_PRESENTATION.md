# 🛡️ Agentic SecOps: Executive Solution Overview
**Agentic AIOps Platform · Powered by Gemini 2.0 & Google ADK**

---

## 🏗️ 1. Architecture: The Agentic Core
Agentic SecOps is built on a **Hybrid Agentic Architecture** that combines three core Google/Industry standards to automate the Security Operations Center (SOC).

```mermaid
graph TD
    A[Case Ingestion] --> B[SOCOrchestrator Agent]
    B -- "Parallel Enrichment (Steps 2-4)" --> C[EnrichmentAgent]
    C -- "MCP Tool" --> D[(SecOps Data)]
    C -- "RAG Method" --> E[(Playbook Library)]
    C -- "MCP Tool" --> F[(Threat Intel)]
    B -- "Analysis (Step 5)" --> G[ThreatAnalystAgent]
    G -- "Synthesis" --> H[Structured Case Report]
    H -- "HITL Gate (Step 6)" --> I[Decision Phase]
    I -- "Remediation (Step 7-8)" --> J[ActionExecutorAgent]
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
| **2** | **Enrichment** | Enrichment | **Parallel**: Fetching raw logs and user data via MCP. |
| **3** | **Playbook RAG** | Enrichment | **Parallel**: Semantic search to find the correct SOAR procedure. |
| **4** | **Threat Intel** | Enrichment | **Parallel**: IP/Domain reputation via Google Threat Intel. |
| **5** | **Synthesis** | Analyst | Gemini reasons across all data for the final Impact Report. |
| **6** | **HITL Review** | Orchestrator | Pauses for human review or triggers Auto-Remediation policy. |
| **7** | **Remediation** | Action Executor | Performs automated containment via EDR and Firewalls. |
| **8** | **Closure** | Action Executor | Final ServiceNow resolution and SecOps case closure. |

---

## 🧪 3. Demo Walkthrough: CASE-001 (Lateral Movement)
*Demonstrating how the principles come together for a Critical Case.*

### 📂 Phase A: Detection & Parallel Enrichment (Steps 1-4)
- **Problem**: Compromised domain admin account accessing 14 workstations sequentially.
- **The Agentic Move**: The `EnrichmentAgent` triggers one **Parallel Enrichment** turn.
  - **MCP (Data)**: Pulls logs showing the lateral movement.
  - **RAG (Knowledge)**: Matches the threat to **PB-003 (Credential Compromise Response)**.
  - **MCP (Intel)**: Flags the attacker's C2 IP via GTI.

### 🧠 Phase B: AI Threat Synthesis (Step 5)
- **Analysis**: Gemini reconciles raw logs with Intel and identifies risk.
- **Blast Radius**: Identifies **14 machines** effectively communicating with the rogue domain.

### ✅ Phase C: HITL & Remediation (Steps 6-8)
- **Human Decision**: Orchestrator pauses. Analyst clicks "✅ Accept Recommendation."
- **ActionExecutor**: Performs remediation and closes the ServiceNow incident.

---

## 📈 4. Key Benefits for the Client
- **90% Latency Reduction**: No more waiting for agents to run sequentially. Steps 2, 3, and 4 happen at once in a single 'Parallel Enrichment' turn.
- **Model Agnostic**: UI and logic use the `ThreatAnalystAgent` persona, allowing you to swap models (Gemini, Vertex AI, etc.) without UI disruption.
- **Zero Re-Analysis Loops**: Direct handover from HITL to Execution ensures the agent never asks "Wait, what happened?" after you approve.
- **Auto-Remediation**: Low/Medium cases can move from Ingestion to Execution in seconds.

> [!TIP]
> **Production Readiness**: Every mock tool in this POC is built on the **Adapter Pattern**, meaning you can swap "Mocks" for "Production APIs" without rewriting any code.
