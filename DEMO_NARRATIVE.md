# Demo Narrative: Agentic SecOps Pipeline (8 Steps)

*Use this guide to explain the demo to your client. Focus on how the agents "hand over" the baton to each other using the shared ADK session state.*

---

### **Step 1: Case Ingestion [SOCOrchestrator]**
- **Speaker Script:** *"We start by ingesting a raw alert from the SIEM. Here, the **SOCOrchestrator** (the brain) takes the first look. It doesn't do the work itself; it's a dispatcher. It looks at the metadata and decides which specialist needs to be called next."*
- **Agent Handover:** Orchestrator calls `transfer_to_agent("EnrichmentAgent")`.

### **Step 2: Data Enrichment [EnrichmentAgent]**
- **Speaker Script:** *"The **EnrichmentAgent** now takes over. It queries the internal asset databases to find out WHO this user is (j.smith) and WHAT this machine is (DESKTOP-DB42). Notice how it's pulling context that raw logs usually miss."*
- **Source:** SIEM Index / Asset Database.

### **Step 3: Playbook Selection [EnrichmentAgent]**
- **Speaker Script:** *"Instead of a static script, the agent uses **RAG (Retrieval-Augmented Generation)** to find the best-fit corporate playbook for this specific pattern. It's comparing 'Lateral Movement' with 50+ available responses to pick the exact one needed (PB-003)."*
- **Source:** Internal Playbook Vector Store.

### **Step 4: Threat Intel Enrichment [EnrichmentAgent]**
- **Speaker Script:** *"Simultaneously, the agent checks external Threat Intel. It finds that the IP being contacted is a known command-and-control server. The investigation is now 'high confidence'."*
- **Source:** Google Threat Intel (GTI) / VirusTotal.

### **Step 5: Impact & Incident Synthesis [ThreatAnalystAgent]**
- **Speaker Script:** *"Now we reach the 'Reasoning Peak'. The **ThreatAnalystAgent** synthesizes all the fragmented data into a human-readable report. It calculates the **Blast Radius** (14 endpoints affected) and proposes exactly what to do."*
- **Agent Handover:** The Orchestrator transfers control to the Analyst to generate the final JSON report.

### **Step 6: HITL Review [Analyst Gate]**
- **Speaker Script:** *"This is where we bridge AI with Human Control. The platform pauses here for corporate governance. For low-risk tasks, it might auto-approve. For a 'Domain Admin' compromise like this, it forces a heartbeat check from a human analyst."*
- **Action:** Manual Approve/Reject or Policy-driven Auto-Approval.

### **Step 7: Agentic Remediation [ActionExecutorAgent]**
- **Speaker Script:** *"Once approved, the **ActionExecutorAgent** takes the steering wheel. It has the credentials to actually disable the account in Active Directory and isolate the 14 machines in the EDR or firewall. This happens in seconds, not hours."*
- **Source:** ServiceNow MCP / CrowdStrike / Palo Alto.

### **Step 8: Automated Case Closure [ActionExecutorAgent]**
- **Speaker Script:** *"Finally, the system closes the loop. It writes a full audit trail back into the ServiceNow incident (INC0041892) and marks the case as resolved. The SOC team now has a perfect record of the AI's actions for compliance."*
- **Action:** ServiceNow Resolve + Audit Trail.

---

### **Explain the "Handover" Concept:**
- **Shared Memory:** Each agent reads and writes to a shared **ADK Session State**. 
- **The "Baton":** Think of the investigation as a relay race. The **Orchestrator** is the coach at the sidelines, and each agent holds the "baton" (the case file) only for their specific leg of the race.
- **Why this matters for clients:** Most automation tools use "logic trees" where if Step A fails, the whole thing stops. In an **Agentic** system, if one enrichment tool is down, the **Orchestrator** can gracefully pivot and ask the agent to try an alternative path.
