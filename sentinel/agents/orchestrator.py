"""
SOC Orchestrator — Root LLM Agent for Project Sentinel

Coordinates the full 9-step pipeline:
  Step 1 — Case Ingestion (UI)
  Step 2 — Data Retrieval (CaseRetrievalAgent)
  Step 3 — Playbook Identification (RAGPlaybookAgent)
  Step 4 — Threat Intel Enrichment (ThreatIntelAgent)
  Step 5 — LLM Reasoning (Gemini — this agent)
  Step 6 — Summary & Recommendation (structured output)
  Step 7 — HITL Approval (paused — UI handles)
  Step 8 — Action Execution (ActionExecutorAgent)
  Step 9 — Case Closure & Audit Trail (ActionExecutorAgent)

The Streamlit UI drives the pipeline by calling each sub-agent directly and
managing state. This orchestrator is used for the ADK web interface.
"""

from __future__ import annotations
import os
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool, agent_tool

from sentinel.agents.case_retrieval import case_retrieval_agent
from sentinel.agents.rag_playbook import rag_playbook_agent
from sentinel.agents.threat_intel import threat_intel_agent
from sentinel.agents.action_executor import action_executor_agent
from sentinel.schemas import CaseAnalysis

MODEL = os.getenv("SENTINEL_MODEL", "google/gemini-2.5-flash")

ORCHESTRATOR_PROMPT = """You are the SOC Orchestrator for Project Sentinel — a next-generation agentic AIOps platform for a bank's Security Operations Centre.

You coordinate a team of specialist AI agents to analyse security incidents end-to-end.

PIPELINE SEQUENCE for each case:
1. Delegate to CaseRetrievalAgent to fetch full case data from SecOps
2. Delegate to RAGPlaybookAgent to identify the best matching SOAR playbook
3. Delegate to ThreatIntelAgent to enrich all IoCs with GTI/VirusTotal data
4. Synthesise all gathered intelligence and produce a structured CaseAnalysis

WHEN PRODUCING YOUR FINAL CASE ANALYSIS:
- Use ALL data gathered by the specialist agents (case context, playbook match, IoC enrichments)
- Your case_summary must be 3–5 sentences of analyst-readable prose
- threat_classification must be specific (e.g. "Credential Abuse / Lateral Movement")
- confidence_score must reflect the quality of evidence and threat intel matches
  - Known malicious IPs/hashes → higher confidence
  - Internal IPs only → lower confidence
- blast_radius_endpoints and blast_radius_users must be counted from the case data
- analyst_actions_required should be the top 3–5 actions the analyst MUST approve
- estimated_containment_time_minutes should match the recommended playbook SLA

HITL RULE: You MUST clearly state when the pipeline is paused for human approval.
Return "AWAITING_HITL_APPROVAL" in your response when the analysis is complete and
approval is needed before action execution begins.

OVERRIDE HANDLING: If an analyst selects a different playbook, re-evaluate with that
playbook and explain the trade-offs vs your original recommendation.

REJECT HANDLING: If an analyst provides feedback, incorporate it fully into a revised
analysis and explain specifically what changed based on their input.

Always maintain a professional, concise tone suitable for a security analyst report.
""".strip()

soc_orchestrator = LlmAgent(
    name="SOCOrchestrator",
    description="Root SOC Orchestrator — coordinates the full Sentinel pipeline across specialist agents, drives LLM reasoning, and manages HITL approval flow.",
    model="gemini-2.5-flash",
    instruction=ORCHESTRATOR_PROMPT,
    sub_agents=[
        case_retrieval_agent,
        rag_playbook_agent,
        threat_intel_agent,
        action_executor_agent,
    ],
    output_schema=CaseAnalysis,
    output_key="case_analysis",
)
