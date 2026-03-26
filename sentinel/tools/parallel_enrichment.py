"""
parallel_enrichment.py — Tools for concurrent SOC data enrichment.
 
This module performs parallel threat intel and data enrichment to minimize
latency in the 8-step pipeline.
"""

import asyncio
import os
import json
from pathlib import Path
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

    # 2. Fetch RAG Playbooks (Requires case context)
    async def fetch_rag(case_context=None):
        print(f"[{_now()}] [RUNNING:STEP:3] Querying Playbook RAG...")
        # If no summary provided, try to extract from case context
        query = case_summary_for_rag
        if not query and case_context:
            title = case_context.get("case", {}).get("title", "")
            desc = case_context.get("case", {}).get("description", "")
            query = f"{title} {desc}".strip()
        
        # Fallback to case_id if still empty
        if not query: query = case_id
        
        playbooks = query_playbook_corpus(query)
        print(f"[{_now()}] [DONE:STEP:3] Playbook Matches Found for query: '{query[:50]}...'")
        return playbooks

    # 3. Fetch Threat Intel
    async def fetch_ti():
        print(f"[{_now()}] [RUNNING:STEP:4] Enriching Threat Intel...")
        try:
            # Avoid circular import with runner.py
            cases_dir = Path(__file__).parent.parent / "data" / "cases"
            fname = case_id.lower().replace("-", "_") + ".json"
            case_path = cases_dir / fname
            
            print(f"[{_now()}] DEBUG: Loading TI case data from {case_path}")
            if case_path.exists():
                with open(case_path, encoding="utf-8") as f:
                    cd = json.load(f)
                iocs = cd.get("iocs", {})
                print(f"[{_now()}] DEBUG: Found IoCs: {iocs}")
                enrichments = bulk_enrich_iocs(
                    ips=iocs.get("ips", []),
                    hashes=iocs.get("hashes", []),
                    domains=iocs.get("domains", [])
                )
            else:
                print(f"[{_now()}] DEBUG: Case file not found for TI enrichment")
                enrichments = {"ips": [], "hashes": [], "domains": []}
                
            print(f"[{_now()}] [DONE:STEP:4] Threat Intel Enrichment Complete.")
            return enrichments
        except Exception as e:
            print(f"[{_now()}] DEBUG: Error in fetch_ti: {e}")
            return {"ips": [], "hashes": [], "domains": []}

    # Run in a semi-parallel sequence to allow RAG to use Case context
    try:
        # Step 2: Fetch Base Case Data first (it's the dependency for a good RAG query)
        secops_data = await fetch_secops()
        
        # Steps 3 & 4: Run RAG and TI in parallel using the retrieved context
        print(f"[{_now()}] ⚡️ Running RAG and Threat Intel in parallel...")
        rag_task = fetch_rag(case_context=secops_data)
        ti_task = fetch_ti()
        
        rag_data, ti_data = await asyncio.gather(rag_task, ti_task, return_exceptions=True)
        
        print(f"[{_now()}] ✅ Parallel Enrichment Complete.")
        
        return {
            "secops_data": secops_data,
            "rag_results": rag_data if not isinstance(rag_data, Exception) else f"Error: {rag_data}",
            "ioc_enrichments": ti_data if not isinstance(ti_data, Exception) else f"Error: {ti_data}"
        }
    except Exception as e:
        print(f"[{_now()}] ❌ Error in parallel enrichment: {e}")
        return {
            "secops_data": f"Error: {e}",
            "rag_results": [],
            "ioc_enrichments": {}
        }

if __name__ == "__main__":
    # Test harness
    res = asyncio.run(run_parallel_enrichment("CASE-001", "lateral movement credential abuse"))
    print(json.dumps(res, indent=2))
