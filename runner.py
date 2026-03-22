"""
runner.py — ADK pipeline runner for Streamlit.

Provides async functions that Streamlit calls to drive each stage of the
9-step Sentinel pipeline. Manages ADK session state, handles streaming
events, and formats agent messages for the UI log.
"""

from __future__ import annotations
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from sentinel.tools.secops_mcp import get_case, list_alerts, get_raw_logs, get_affected_assets
from sentinel.tools.rag_tool import query_playbook_corpus
from sentinel.tools.gti_mcp import enrich_ip, enrich_hash, enrich_domain
from sentinel.tools.snow_mcp import add_worknote, close_incident, get_incident_state
from sentinel.tools.secops_mcp import trigger_playbook, update_case_status

# ── Gemini direct call (no ADK overhead for the main analysis) ─────────────────

def _get_gemini_model():
    """Return configured Gemini model string."""
    return os.getenv("SENTINEL_MODEL", "gemini-2.5-flash")

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _load_case_data(case_id: str) -> dict:
    """Load case JSON fixture directly."""
    data_dir = Path(__file__).parent / "sentinel" / "data" / "cases"
    fname = case_id.lower().replace("-", "_") + ".json"
    with open(data_dir / fname, encoding="utf-8") as f:
        return json.load(f)

# ── Step-by-step pipeline functions ───────────────────────────────────────────

def step_retrieve_case(case_id: str) -> dict:
    """Step 2: Retrieve case data via mock SecOps MCP."""
    case = get_case(case_id)
    alerts = list_alerts(case_id)
    logs = get_raw_logs(case_id)
    assets = get_affected_assets(case_id)
    return {
        "case": case,
        "alerts": alerts,
        "logs": logs,
        "assets": assets,
        "raw_case": _load_case_data(case_id),
    }


def step_query_rag(case_id: str, threat_context: str) -> list[dict]:
    """Step 3: Query playbook corpus with threat context."""
    results = query_playbook_corpus(threat_context, top_k=3)
    return results


def step_enrich_iocs(case_id: str) -> dict:
    """Step 4: Enrich all IoCs for the case."""
    raw = _load_case_data(case_id)
    iocs = raw.get("iocs", {})
    enriched = {"ips": [], "hashes": [], "domains": []}
    for ip in iocs.get("ips", []):
        enriched["ips"].append(enrich_ip(ip))
    for h in iocs.get("hashes", []):
        enriched["hashes"].append(enrich_hash(h))
    for d in iocs.get("domains", []):
        enriched["domains"].append(enrich_domain(d))
    return enriched


def step_call_gemini(case_id: str, case_data: dict, rag_results: list, ioc_data: dict,
                     override_playbook: str | None = None,
                     analyst_feedback: str | None = None) -> dict:
    """
    Step 5+6: Call Gemini to produce structured CaseAnalysis.
    Returns the raw Gemini response as a dict (parsed from JSON).
    """
    import google.generativeai as genai

    api_key = os.getenv("GOOGLE_API_KEY")
    use_vertex = os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "FALSE").upper() == "TRUE"

    top_playbook = rag_results[0] if rag_results else {}
    if override_playbook:
        # Find the override in the results list or use top
        override_match = next((r for r in rag_results if r["playbook_id"] == override_playbook), top_playbook)
        selected_playbook = override_match
        override_note = f"\n\nNOTE: The analyst has OVERRIDDEN the recommendation and selected {override_playbook}. Evaluate with this playbook and explain any trade-offs vs the original recommendation."
    else:
        selected_playbook = top_playbook
        override_note = ""

    feedback_note = ""
    if analyst_feedback:
        feedback_note = f"\n\nANALYST FEEDBACK FOR REVISION: {analyst_feedback}\nRevise your analysis incorporating this feedback specifically."

    all_iocs_flat = []
    for ip_data in ioc_data.get("ips", []):
        all_iocs_flat.append({
            "indicator": ip_data.get("ip", ""),
            "indicator_type": "ip",
            "reputation_score": ip_data.get("reputation_score", 0),
            "malware_family": ip_data.get("malware_family"),
            "campaign": ip_data.get("campaign"),
            "verdict": ip_data.get("verdict", "Unknown"),
            "mitre_techniques": ip_data.get("mitre_techniques", []),
        })
    for h_data in ioc_data.get("hashes", []):
        all_iocs_flat.append({
            "indicator": h_data.get("hash", ""),
            "indicator_type": "hash",
            "reputation_score": h_data.get("reputation_score", 0),
            "malware_family": h_data.get("malware_family"),
            "campaign": h_data.get("campaign"),
            "verdict": h_data.get("verdict", "Unknown"),
            "mitre_techniques": h_data.get("mitre_techniques", []),
        })
    for d_data in ioc_data.get("domains", []):
        all_iocs_flat.append({
            "indicator": d_data.get("domain", ""),
            "indicator_type": "domain",
            "reputation_score": d_data.get("reputation_score", 0),
            "malware_family": d_data.get("malware_family"),
            "campaign": d_data.get("campaign"),
            "verdict": d_data.get("verdict", "Unknown"),
            "mitre_techniques": d_data.get("mitre_techniques", []),
        })

    prompt = f"""You are a senior SOC analyst AI. Analyse the following security case and produce a structured JSON response.

CASE DATA:
{json.dumps(case_data["case"], indent=2)}

ALERTS ({len(case_data["alerts"])} total):
{json.dumps(case_data["alerts"], indent=2)}

AFFECTED ASSETS:
{json.dumps(case_data["assets"], indent=2)}

TOP PLAYBOOK MATCH (relevance score: {selected_playbook.get('relevance_score', 0)}):
{json.dumps(selected_playbook, indent=2)}

ALL PLAYBOOK CANDIDATES:
{json.dumps(rag_results, indent=2)}

IOC ENRICHMENTS:
{json.dumps(all_iocs_flat, indent=2)}
{override_note}
{feedback_note}

Produce a JSON response matching this exact schema (all fields required):
{{
  "case_id": "<case_id>",
  "case_summary": "<3-5 sentence analyst-readable prose summary>",
  "threat_classification": "<specific classification e.g. Credential Abuse / Lateral Movement>",
  "severity": "<Critical|High|Medium|Low>",
  "mitre_techniques": [
    {{"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Defense Evasion"}}
  ],
  "blast_radius_endpoints": <int>,
  "blast_radius_users": <int>,
  "recommended_playbook_id": "<PB-xxx>",
  "recommended_playbook_name": "<name>",
  "playbook_rationale": "<1-2 sentence explanation>",
  "confidence_score": <0.0-1.0>,
  "ioc_enrichments": [
    {{"indicator": "<value>", "indicator_type": "<ip|hash|domain>", "reputation_score": <int>, "malware_family": <str|null>, "campaign": <str|null>, "verdict": "<verdict>", "mitre_techniques": []}}
  ],
  "analyst_actions_required": ["<action 1>", "<action 2>"],
  "estimated_containment_time_minutes": <int>
}}

Respond with ONLY the JSON object. No markdown, no explanation."""

    if use_vertex:
        import vertexai
        from vertexai.generative_models import GenerativeModel
        project = os.getenv("GOOGLE_CLOUD_PROJECT")
        location = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
        vertexai.init(project=project, location=location, api_key=api_key)
        model = GenerativeModel(_get_gemini_model())
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json", "temperature": 0.2},
        )
        raw_text = response.text
    else:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(_get_gemini_model())
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                response_mime_type="application/json",
                temperature=0.2,
            ),
        )
        raw_text = response.text

    # Parse JSON response
    try:
        result = json.loads(raw_text)
    except json.JSONDecodeError:
        # Try to extract JSON from response
        import re
        match = re.search(r'\{.*\}', raw_text, re.DOTALL)
        if match:
            result = json.loads(match.group())
        else:
            raise ValueError(f"Could not parse Gemini response as JSON: {raw_text[:200]}")

    return result


def step_execute_actions(case_id: str, analysis: dict, analyst_name: str = "SOC Analyst") -> dict:
    """Step 8: Execute SOAR playbook and update SNOW."""
    playbook_id = analysis.get("recommended_playbook_id", "PB-003")
    raw_case = _load_case_data(case_id)
    snow_ref = raw_case.get("snow_incident_ref", "INC0000000")

    # 1. Trigger playbook
    exec_result = trigger_playbook(playbook_id, case_id)

    # 2. Add SNOW worknote
    worknote_text = (
        f"SENTINEL AI — Automated Action Report\n"
        f"Playbook Executed: {playbook_id} — {analysis.get('recommended_playbook_name', '')}\n"
        f"Analyst Approval: {analyst_name} at {_now_iso()}\n"
        f"Confidence Score: {analysis.get('confidence_score', 0)*100:.0f}%\n"
        f"Execution ID: {exec_result.get('execution_id', 'N/A')}\n"
        f"Actions: {len(exec_result.get('action_steps', []))} steps initiated"
    )
    add_worknote(snow_ref, worknote_text, author="Sentinel Action Executor (AI)")

    return {"execution": exec_result, "snow_ref": snow_ref}


def step_close_case(case_id: str, analysis: dict, execution: dict,
                    analyst_name: str = "SOC Analyst",
                    hitl_decision: str = "Accepted") -> dict:
    """Step 9: Close SNOW ticket and update SecOps case."""
    raw_case = _load_case_data(case_id)
    snow_ref = raw_case.get("snow_incident_ref", "INC0000000")
    exec_result = execution.get("execution", {})

    close_notes = (
        f"SENTINEL AI — Case Resolution Report\n"
        f"{'='*60}\n"
        f"Case ID: {case_id}\n"
        f"Threat Classification: {analysis.get('threat_classification', '')}\n"
        f"Severity: {analysis.get('severity', '')}\n\n"
        f"SUMMARY:\n{analysis.get('case_summary', '')}\n\n"
        f"PLAYBOOK EXECUTED: {analysis.get('recommended_playbook_id')} — {analysis.get('recommended_playbook_name')}\n"
        f"Rationale: {analysis.get('playbook_rationale', '')}\n\n"
        f"HITL DECISION: {hitl_decision} by {analyst_name} at {_now_iso()}\n"
        f"Confidence Score: {analysis.get('confidence_score', 0)*100:.0f}%\n\n"
        f"ACTIONS EXECUTED: {len(exec_result.get('action_steps', []))} steps\n"
        + "\n".join(
            f"  {s['step']}. {s['action']} → {s['status'].upper()} ({s['duration_seconds']}s)"
            for s in exec_result.get("action_steps", [])
        ) +
        f"\n\nMITRE ATT&CK TECHNIQUES:\n"
        + ", ".join(t.get("technique_id", "") for t in analysis.get("mitre_techniques", [])) +
        f"\n\nESTIMATED CONTAINMENT TIME: {analysis.get('estimated_containment_time_minutes', 0)} minutes\n"
        f"BLAST RADIUS: {analysis.get('blast_radius_endpoints', 0)} endpoints, {analysis.get('blast_radius_users', 0)} users"
    )

    close_result = close_incident(snow_ref, close_notes)
    update_case_status(case_id, "RESOLVED", f"Resolved via Sentinel AI — {analysis.get('recommended_playbook_id')}")

    return {
        "snow_ref": snow_ref,
        "close_result": close_result,
        "close_notes": close_notes,
        "snow_state": get_incident_state(snow_ref),
    }
