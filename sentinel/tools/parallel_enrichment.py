"""
parallel_enrichment.py — Tools for concurrent SOC data enrichment.

This module provides a unified tool that triggers multiple READ operations 
(SecOps, RAG, Threat Intel) in parallel using asyncio.gather, significantly
reducing latency in the 9-step pipeline.
"""

import asyncio
import os
import json
from datetime import datetime, timezone

# Import existing tool functions
from sentinel.tools.secops_mcp import (
    get_case, list_alerts, get_raw_logs, get_affected_assets,
)
from sentinel.tools.rag_tool import query_playbook_corpus
from sentinel.tools.gti_mcp import bulk_enrich_iocs

def _now():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")

async def run_parallel_enrichment(case_id: str, case_summary_for_rag: str = ""):
    """
    Perform deep case enrichment by running SecOps retrieval, RAG playbook search,
    and Threat Intel enrichment concurrently.
    
    Args:
        case_id: The unique identifier for the security case.
        case_summary_for_rag: Optional summary or threat indicators to optimize RAG search.
    """
    print(f"[{_now()}] ⚡️ Starting Parallel Enrichment for {case_id}...")
    
    # 1. Fetch Core SecOps Data (Internal sequence)
    async def fetch_secops():
        print(f"[{_now()}] [RUNNING:STEP:2] Fetching SecOps Case Data...")
        case = get_case(case_id)
        alerts = list_alerts(case_id)
        logs = get_raw_logs(case_id)
        assets = get_affected_assets(case_id)
        print(f"[{_now()}] [DONE:STEP:2] SecOps Data Ready.")
        return {"case": case, "alerts": alerts, "logs": logs, "assets": assets}

    # 2. Fetch RAG Playbooks
    async def fetch_rag():
        print(f"[{_now()}] [RUNNING:STEP:3] Querying Playbook RAG...")
        # If no summary provided, use case_id as fallback query
        query = case_summary_for_rag if case_summary_for_rag else case_id
        playbooks = query_playbook_corpus(query)
        print(f"[{_now()}] [DONE:STEP:3] Playbook Matches Found.")
        return playbooks

    # 3. Fetch Threat Intel
    async def fetch_ti():
        print(f"[{_now()}] [RUNNING:STEP:4] Enriching Threat Intel...")
        # We need the IoCs first. For POC, we can pre-fetch them or assume they are in the case file.
        # To be truly parallel with step 2, we load the case fixture locally if it exists.
        from runner import _load_case_data
        cd = _load_case_data(case_id)
        iocs = cd.get("iocs", {})
        enrichments = bulk_enrich_iocs(
            ips=iocs.get("ips", []),
            hashes=iocs.get("hashes", []),
            domains=iocs.get("domains", [])
        )
        print(f"[{_now()}] [DONE:STEP:4] Threat Intel Enrichment Complete.")
        return enrichments

    # Run all three enrichment tracks in parallel
    results = await asyncio.gather(
        fetch_secops(),
        fetch_rag(),
        fetch_ti(),
        return_exceptions=True
    )
    
    secops_data, rag_data, ti_data = results
    
    print(f"[{_now()}] ✅ Parallel Enrichment Complete.")
    
    return {
        "secops_data": secops_data if not isinstance(secops_data, Exception) else f"Error: {secops_data}",
        "rag_results": rag_data if not isinstance(rag_data, Exception) else f"Error: {rag_data}",
        "ioc_enrichments": ti_data if not isinstance(ti_data, Exception) else f"Error: {ti_data}"
    }

if __name__ == "__main__":
    # Test harness
    res = asyncio.run(run_parallel_enrichment("CASE-001", "lateral movement credential abuse"))
    print(json.dumps(res, indent=2))
