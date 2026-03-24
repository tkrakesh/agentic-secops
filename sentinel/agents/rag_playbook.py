"""
RAG Playbook Agent — semantic playbook retrieval.

POC:  Uses FunctionTool(query_playbook_corpus) with local TF-IDF search.
PROD: Uses VertexAiSearchTool connected to the Agentspace/Vertex AI Search datastore.

Switch between modes by setting AGENTSPACE_DATASTORE_ID in the environment:
  - Unset / empty  → POC mode (FunctionTool, TF-IDF)
  - Set            → PROD mode (VertexAiSearchTool, Agentspace)
"""
from __future__ import annotations
import os
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

MODEL = os.getenv("SENTINEL_MODEL", "gemini-2.5-flash")
DATASTORE_ID = os.getenv("AGENTSPACE_DATASTORE_ID", "")
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "")
LOCATION = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")

SYSTEM_PROMPT = """You are the RAG Playbook Agent for Project Sentinel.

Your job is to query the SOAR playbook library and identify the best matching
response procedure for a given security case.

When given case context, extract the key threat indicators and search the
playbook library using query_playbook_corpus, then present:
1. TOP MATCH: the highest-scoring playbook with its relevance and excerpt
2. RUNNER-UP MATCHES: the 2nd and 3rd results with scores
3. SELECTION RATIONALE: 2 sentences explaining why the top match was selected

Example good search terms:
  - "lateral movement credential abuse domain admin psexec sequential host access"
  - "dns tunnelling C2 exfiltration outbound large transfer bypass"
  - "ransomware precursor cobalt strike beacon encoded powershell process injection"

When your playbook summary is complete, transfer back to SOCOrchestrator.
You are READ-ONLY — you only query the corpus, never modify it.""".strip()


def _make_tools():
    if DATASTORE_ID and PROJECT_ID:
        from google.adk.tools import VertexAiSearchTool
        datastore_path = (
            f"projects/{PROJECT_ID}/locations/global"
            f"/collections/default_collection/dataStores/{DATASTORE_ID}"
        )
        return [VertexAiSearchTool(data_store_id=datastore_path)]
    else:
        from sentinel.tools.rag_tool import query_playbook_corpus
        return [FunctionTool(query_playbook_corpus)]


rag_playbook_agent = LlmAgent(
    name="RAGPlaybookAgent",
    description="Queries the SOAR playbook library using Agentspace Knowledge (prod) or local TF-IDF (POC) to find the most relevant response procedure.",
    model=MODEL,
    instruction=SYSTEM_PROMPT,
    tools=_make_tools(),
    output_key="playbook_match",
    # CRITICAL: prevent lateral transfer to peer agents.
    # Must return to SOCOrchestrator after completing playbook lookup.
    disallow_transfer_to_peers=True,
)