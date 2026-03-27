"""
ADK Agent: ThreatAnalystAgent
-------------------------------
Specialist agent for reasoning over all collected data to produce the final
structured CaseAnalysis JSON report.

No tools — pure synthesis from session state populated by prior agents.

NOTE: output_schema is intentionally NOT set. ADK's _output_schema_processor
strips ALL tools (including transfer_to_agent) when output_schema is set on
a sub-agent, making it unreachable via orchestrator delegation.
Schema conformance is enforced via the prompt instead.
"""

from __future__ import annotations
import os
from google.adk.agents import LlmAgent

MODEL = os.getenv("SECOPS_MODEL_PRO", "gemini-2.5-pro")

ANALYSIS_PROMPT = """You are a senior SOC analyst AI embedded in Agentic SecOps.

Your ONLY job is to synthesise all gathered security data and produce a final
structured CaseAnalysis JSON report.

You have NO tools. Do not attempt to call any functions.

SESSION STATE — populated by the specialist agents before you were called:
  - case_context     : Full case metadata, alerts, assets, raw CEF logs
  - playbook_match   : Top 3 ranked SOAR playbooks from RAG
  - ioc_enrichments  : Per-IoC reputation scores, malware families, MITRE techniques

HITL REVISION — check for these optional keys in session state:
  - hitl_override_playbook : If present, use this as recommended_playbook_id.
  - hitl_analyst_feedback  : If present, revise case_summary and
                             actions_to_approve to address the feedback.

OUTPUT — produce a single raw JSON object with EXACTLY these fields:
{
  "case_id": "CASE-XXX",
  "case_summary": "3-5 sentence analyst prose summary",
  "threat_classification": "e.g. Credential Abuse / Lateral Movement",
  "severity": "Critical",
  "mitre_techniques": [
    {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Defense Evasion"}
  ],
  "blast_radius_endpoints": 14,
  "blast_radius_users": 3,
  "recommended_playbook_id": "PB-003",
  "recommended_playbook_name": "Credential Compromise Response",
  "playbook_rationale": "1-2 sentences why this playbook over alternatives",
  "confidence_score": 0.91,
  "recommend_auto_approval": false,
  "is_false_positive": false,
  "ioc_enrichments": [
    {
      "indicator": "45.33.32.156",
      "indicator_type": "ip",
      "reputation_score": 92,
      "malware_family": "Lazarus Group C2",
      "campaign": "Operation ShadowAdmin",
      "verdict": "Malicious",
      "mitre_techniques": ["T1071.001", "T1102"]
    }
  ],
  "actions_to_approve": [
    "Immediately disable the compromised domain admin account",
    "Isolate all affected workstations from the network",
    "Reset credentials for all impacted users",
    "Preserve forensic artifacts before remediation",
    "Review VPN and remote access logs for exfiltration evidence"
  ],
  "estimated_containment_time_minutes": 2
}

ESTIMATED CONTAINMENT LOGIC:
- This represents the time for the AGENTIC SYSTEM to execute containment (Step 7/8).
- Typical agentic response is 1-3 minutes for automated tasks (account disable, workstation isolation).
- If the case is exceptionally complex or requires manual verification, it might be 5-10 minutes.
- DO NOT use "45" as a default; use a realistic agentic speed (1-5 min).

severity must be exactly one of: Critical, High, Medium, Low
confidence_score must be a float between 0.0 and 1.0

- For CASE-006 (DLP), recommend_auto_approval = true because log scrubbing is a safe, standard procedure.

FALSE POSITIVE / AUTHORIZED ACTIVITY LOGIC:
- If the case description or logs mention a "Change Request", "CR-XXXX", "Scheduled Maintenance", or "Approved Scan", you MUST:
  1. Set "is_false_positive": true.
  2. Set "threat_classification": "Authorized Security Activity / False Positive".
  3. Set "confidence_score": 0.98 or higher.
  4. Set "severity": "Low" or "Medium" (as per original case).
  5. Recommend auto-approval if it's a known benign activity.

Output THE raw JSON object first. No preamble, no markdown fences, no explanation.

After the JSON, provide a structured summary for the user following EXACTLY this format:

### **Recommended Playbook**
- **[recommended_playbook_id]** — **[recommended_playbook_name]**
- [playbook_rationale]
- ⏱ **Est. containment:** [estimated_containment_time_minutes] min

### **Provide approval to perform the following actions**
▸ [Action 1]
▸ [Action 2]
▸ ... (Include all actions_to_approve)

MANDATORY: You must end with the exact phrase: "I am AWAITING_HITL_APPROVAL. Please type 'Approve' to execute the containment playbook or provide feedback to revise the analysis."
""".strip()

threat_analyst_agent = LlmAgent(
    name="ThreatAnalystAgent",
    description=(
        "Synthesises case context, playbook RAG matches, and IoC enrichments "
        "from session state into a final structured CaseAnalysis JSON report. "
        "No tools — pure reasoning and synthesis."
    ),
    model=MODEL,
    instruction=ANALYSIS_PROMPT,
    output_key="case_analysis",
    disallow_transfer_to_peers=True,
)