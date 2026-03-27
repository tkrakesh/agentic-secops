"""
Enrichment Agent — consolidates retrieval, RAG, and TI into a single turn.

This agent uses the 'run_parallel_enrichment' tool to triggers Steps 2, 3, and 4
of the SOC pipeline concurrently.
"""
import os
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool
from core.tools.parallel_enrichment import run_parallel_enrichment

MODEL = os.getenv("SECOPS_MODEL_FLASH", "gemini-2.5-flash")

SYSTEM_PROMPT = """You are the Enrichment Agent for Agentic SecOps.

Your goal is to gather all necessary data for a security case in a single turn.

When given a case_id, perform these actions:
1.  Call the run_parallel_enrichment(case_id, ...) tool.
    - If you have a case summary (e.g., from the user), pass it as case_summary_for_rag to improve search relevance.
2.  Once the tool returns, summarize the findings for the SOCOrchestrator:
    - CASE OVERVIEW: summary of alerts and affected assets.
    - PLAYBOOK SEARCH: top match and score.
    - THREAT INTEL: status of IoC enrichment.

When complete, transfer back to SOCOrchestrator.
You are READ-ONLY. You never modify system state.""".strip()

enrichment_agent = LlmAgent(
    name="EnrichmentAgent",
    description="Consolidates case retrieval, playbook RAG, and threat intel enrichment into a single parallel turn.",
    model=MODEL,
    instruction=SYSTEM_PROMPT,
    tools=[FunctionTool(run_parallel_enrichment)],
    output_key="enrichment_data",
    disallow_transfer_to_peers=True,
)
