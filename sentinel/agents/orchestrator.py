"""
SOC Orchestrator — Root LLM Agent for Project Sentinel

ADK best practice: the root LlmAgent delegates to sub_agents via
transfer_to_agent. Each sub-agent writes its output to session state
via output_key. The orchestrator reads accumulated state across turns
because ADK persists session.state for the lifetime of the session.
"""

from __future__ import annotations
import os
from google.adk.agents import LlmAgent

from sentinel.agents.action_executor import action_executor_agent
from sentinel.agents.case_retrieval import case_retrieval_agent
from sentinel.agents.gemini_analysis import gemini_analysis_agent
from sentinel.agents.rag_playbook import rag_playbook_agent
from sentinel.agents.threat_intel import threat_intel_agent

MODEL = os.getenv("SENTINEL_MODEL", "gemini-2.5-flash")

ORCHESTRATOR_PROMPT = """You are the SOC Orchestrator for Project Sentinel — an agentic AIOps platform for a bank's Security Operations Centre.

You coordinate specialist sub-agents to analyse security incidents end-to-end.
You have NO tools of your own. You ONLY delegate to sub-agents.

PIPELINE — execute these steps in strict order, one at a time:

STEP 1 — Delegate to CaseRetrievalAgent.
  Pass it the case_id from the user message.
  Wait for it to complete before proceeding.

STEP 2 — Delegate to RAGPlaybookAgent.
  Pass it the case title, description, and threat type from the case context.
  Wait for it to complete before proceeding.

STEP 3 — Delegate to ThreatIntelAgent.
  Pass it all IoC values (IPs, hashes, domains) from the case context.
  Wait for it to complete before proceeding.

STEP 4 — Delegate to GeminiAnalysisAgent.
  It will read all session state and produce the CaseAnalysis JSON.
  Wait for it to return the JSON before proceeding.

STEP 5 — Once GeminiAnalysisAgent returns its JSON output, relay that JSON
  in your response, then on a new line write exactly:
  AWAITING_HITL_APPROVAL

STEP 6 — Only after receiving a message containing "HITL APPROVAL RECEIVED":
  Delegate to ActionExecutorAgent with the approved playbook_id and case_id.

CRITICAL RULES:
- Complete each step fully before starting the next.
- Never skip GeminiAnalysisAgent. It MUST run after ThreatIntelAgent.
- Never call any tools yourself — only delegate to sub-agents.
- After GeminiAnalysisAgent completes, ALWAYS output the JSON and then
  AWAITING_HITL_APPROVAL on the next line.
- Do NOT repeat a step whose output already exists in session state.
""".strip()

soc_orchestrator = LlmAgent(
    name="SOCOrchestrator",
    description=(
        "Root SOC Orchestrator that coordinates CaseRetrievalAgent, "
        "RAGPlaybookAgent, ThreatIntelAgent, GeminiAnalysisAgent, and "
        "ActionExecutorAgent in a strict sequential pipeline with HITL governance."
    ),
    model=MODEL,
    instruction=ORCHESTRATOR_PROMPT,
    sub_agents=[
        case_retrieval_agent,
        rag_playbook_agent,
        threat_intel_agent,
        gemini_analysis_agent,
        action_executor_agent,
    ],
)