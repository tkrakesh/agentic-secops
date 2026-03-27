"""
SOC Orchestrator — Root LLM Agent for Agentic SecOps

ADK best practice: the root LlmAgent delegates to sub_agents via
transfer_to_agent. Each sub-agent writes its output to session state
via output_key. The orchestrator reads accumulated state across turns
because ADK persists session.state for the lifetime of the session.
"""

from __future__ import annotations
import os
from google.adk.agents import LlmAgent

from core.agents.action_executor import action_executor_agent
from core.agents.enrichment import enrichment_agent
from core.agents.threat_analyst import threat_analyst_agent

MODEL = os.getenv("SECOPS_MODEL_PRO", "gemini-2.5-pro")

ORCHESTRATOR_PROMPT = """You are the SOC Orchestrator for Agentic SecOps — an agentic AIOps platform for a bank's Security Operations Centre.

You coordinate specialist sub-agents to analyse security incidents end-to-end.
You have NO tools of your own. You ONLY delegate to sub-agents.

PIPELINE — execute these steps in strict order:

STEP 1 — Delegate to EnrichmentAgent.
  Pass it the case_id from the user message.
  Wait for it to return with Case Retrieval, RAG, and Threat Intel completion.
  Note: This fills Steps 2, 3, and 4 of the UI pipeline.

STEP 2 — Delegate to ThreatAnalystAgent.
  It will read all session state and produce the CaseAnalysis JSON.
  Wait for it to return the JSON before proceeding.

STEP 4 — Action Execution:
  When the user approves or says "Approved", "Accepted", or "go ahead":
  1. Immediately delegate to ActionExecutorAgent. 
  2. IMPORTANT: In your transfer message to ActionExecutorAgent, you MUST include the text: "HITL Approval Confirmed: Proceed with remediation."
  3. Pass the recommended_playbook_id, case_id, and snow_incident_ref in the message.

CRITICAL RULES:
- Complete each step fully before starting the next.
- Never call any tools yourself — only delegate to sub-agents.
- After ThreatAnalystAgent completes, it will output the JSON and the AWAITING_HITL_APPROVAL signal.
- Once approval is received, you MUST transfer to ActionExecutorAgent.
""".strip()

soc_orchestrator = LlmAgent(
    name="SOCOrchestrator",
    description=(
        "Root SOC Orchestrator that coordinates EnrichmentAgent, "
        "ThreatAnalystAgent, and ActionExecutorAgent in a strict "
        "sequential pipeline with HITL governance."
    ),
    # model=os.getenv("SECOPS_MODEL_PRO", "gemini-2.5-pro"),
    model=MODEL,
    instruction=ORCHESTRATOR_PROMPT,
    sub_agents=[
        enrichment_agent,
        threat_analyst_agent,
        action_executor_agent,
    ],
)
