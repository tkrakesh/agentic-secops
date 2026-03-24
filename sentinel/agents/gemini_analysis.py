"""
ADK Agent: GeminiAnalysisAgent
-------------------------------
Specialist agent for reasoning over all collected data to produce the final
structured CaseAnalysis JSON.

No tools — pure synthesis from session state populated by prior agents.

NOTE: output_schema is intentionally NOT set. ADK's _output_schema_processor
strips ALL tools (including transfer_to_agent) when output_schema is set on
a sub-agent, making it unreachable via orchestrator delegation.
Schema conformance is enforced via the prompt instead.
"""

from __future__ import annotations
import os
from google.adk.agents import LlmAgent

MODEL = os.getenv("SENTINEL_MODEL", "gemini-2.5-flash")

ANALYSIS_PROMPT = """You are a senior SOC analyst AI embedded in Project Sentinel.

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
                             analyst_actions_required to address the feedback.

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
  "analyst_actions_required": [
    "Immediately disable the compromised domain admin account",
    "Isolate all affected workstations from the network",
    "Reset credentials for all impacted users",
    "Preserve forensic artifacts before remediation",
    "Review VPN and remote access logs for exfiltration evidence"
  ],
  "estimated_containment_time_minutes": 45
}

severity must be exactly one of: Critical, High, Medium, Low
confidence_score must be a float between 0.0 and 1.0

Output ONLY the raw JSON object. No preamble, no markdown fences, no explanation.
After outputting the JSON, transfer back to SOCOrchestrator."""

gemini_analysis_agent = LlmAgent(
    name="GeminiAnalysisAgent",
    description=(
        "Synthesises case context, playbook RAG matches, and IoC enrichments "
        "from session state into a final structured CaseAnalysis JSON report. "
        "No tools — pure reasoning and synthesis."
    ),
    model=MODEL,
    instruction=ANALYSIS_PROMPT,
    output_key="case_analysis",
    # CRITICAL: prevent lateral transfer to peer agents.
    # Must return to SOCOrchestrator after producing the CaseAnalysis JSON.
    disallow_transfer_to_peers=True,
)