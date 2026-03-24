"""
runner.py — ADK pipeline runner for Streamlit.

ADK best practice: a single Runner.run_async() call per user turn.
The SOCOrchestrator delegates to sub-agents internally via transfer_to_agent.
ADK persists session state across turns so the orchestrator accumulates
output_key values (case_context, playbook_match, ioc_enrichments, case_analysis)
as it progresses through the pipeline.

runner.py intercepts the ADK Event stream to:
  1. Extract tool call/response data for UI state panels
  2. Detect pipeline step transitions by event.author
  3. Detect the AWAITING_HITL_APPROVAL signal to pause for human review
  4. Resume after HITL decision for action execution
"""

from __future__ import annotations
import json
import re
import os
import asyncio
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(override=True)

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from sentinel.agents.orchestrator import soc_orchestrator

# Global session service — persists state across Streamlit re-runs
_session_service = InMemorySessionService()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_case_data(case_id: str) -> dict:
    data_dir = Path(__file__).parent / "sentinel" / "data" / "cases"
    fname = case_id.lower().replace("-", "_") + ".json"
    if not (data_dir / fname).exists():
        return {}
    with open(data_dir / fname, encoding="utf-8") as f:
        return json.load(f)


def _extract_json(text: str) -> dict | None:
    """Extract the first complete JSON object from a text string."""
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except Exception:
            pass
    return None


def _unwrap_tool_response(resp: dict, prefer_list: bool = False, tool_name: str = ""):
    """Unwrap ADK tool response envelope to get the actual data."""
    if not isinstance(resp, dict):
        return [resp] if prefer_list and not isinstance(resp, list) else resp
    for k in ["result", "value", "list", "items", "alerts", "assets", "logs", tool_name]:
        if k in resp:
            val = resp[k]
            return [val] if prefer_list and not isinstance(val, list) else val
    if len(resp) == 1:
        val = list(resp.values())[0]
        return [val] if prefer_list and not isinstance(val, list) else val
    return [resp] if prefer_list else resp


async def run_adk_pipeline(
    case_id: str,
    session_id: str,
    analyst_name: str,
    yield_delay: float = 0.05,
):
    """
    Run the full SOC analysis pipeline via the SOCOrchestrator root agent.

    ADK handles all sub-agent delegation internally via transfer_to_agent.
    This function yields UI update dicts for Streamlit to render.
    """
    runner = Runner(
        app_name="sentinel-soc",
        agent=soc_orchestrator,
        session_service=_session_service,
    )

    # Create session with case_id pre-loaded in state
    await _session_service.create_session(
        state={"case_id": case_id},
        app_name="sentinel-soc",
        user_id=analyst_name,
        session_id=session_id,
    )

    yield {"type": "log", "agent": "ORCHESTRATOR", "message": f"Pipeline initiated for {case_id}"}
    yield {"type": "step", "step": 1}

    # Local state mirrors — built from tool responses in the event stream
    case_data = {
        "case": {}, "alerts": [], "logs": "",
        "assets": [], "raw_case": _load_case_data(case_id),
    }
    rag_results = []
    ioc_data = {"ips": [], "hashes": [], "domains": []}

    # Single user message — ADK orchestrator handles the full pipeline
    query = (
        f"Please analyse case {case_id} end-to-end following your pipeline sequence. "
        f"The case_id is {case_id}."
    )
    content = types.Content(role="user", parts=[types.Part.from_text(text=query)])

    try:
        async for event in runner.run_async(
            session_id=session_id,
            user_id=analyst_name,
            new_message=content,
        ):
            author = event.author.upper() if event.author else "SYSTEM"

            # ── Pipeline step tracking by event author ────────────────────────
            if author == "CASERETRIEVALAGENT":
                yield {"type": "step", "step": 2}
            elif author == "RAGPLAYBOOKAGENT":
                yield {"type": "step", "step": 3}
            elif author == "THREATINTELAGENT":
                yield {"type": "step", "step": 4}
            elif author == "GEMINIANALYSISAGENT":
                yield {"type": "step", "step": 5}
            elif author == "SOCORCHESTRATOR":
                yield {"type": "step", "step": 5}

            if not event.content or not event.content.parts:
                continue

            for part in event.content.parts:

                # ── Tool calls — log to agent panel ──────────────────────────
                if part.function_call:
                    name = part.function_call.name
                    if name != "transfer_to_agent":
                        yield {"type": "log", "agent": author, "message": f"→ invoking tool: {name}(...)"}
                        await asyncio.sleep(yield_delay)

                # ── Tool responses — extract data for UI state ────────────────
                elif part.function_response:
                    name = part.function_response.name

                    # Normalise the protobuf response to a plain dict
                    try:
                        from google.protobuf.json_format import MessageToDict
                        resp = (
                            MessageToDict(part.function_response.response._pb)
                            if hasattr(part.function_response.response, "_pb")
                            else dict(part.function_response.response)
                        )
                    except Exception:
                        resp = (
                            dict(part.function_response.response)
                            if hasattr(part.function_response.response, "items")
                            else {}
                        )

                    # SecOps tools — Case Retrieval
                    if name == "get_case":
                        case_data["raw_case"] = resp
                    elif name == "list_alerts":
                        case_data["alerts"] = _unwrap_tool_response(resp, True, name)
                    elif name == "get_raw_logs":
                        case_data["logs"] = _unwrap_tool_response(resp, False, name)
                    elif name == "get_affected_assets":
                        case_data["assets"] = _unwrap_tool_response(resp, True, name)
                        yield {"type": "state", "key": "case_data", "data": case_data}
                        yield {
                            "type": "log", "agent": "CASE-RETRIEVAL",
                            "message": f"✓ Fetched {len(case_data['alerts'])} alerts and {len(case_data['assets'])} assets.",
                        }

                    # RAG tool — Playbook match
                    elif name == "query_playbook_corpus":
                        lst = _unwrap_tool_response(resp, True, name)
                        if isinstance(lst, list):
                            rag_results.extend(lst)
                        yield {"type": "state", "key": "rag_results", "data": rag_results}
                        top = rag_results[0] if rag_results else {}
                        yield {
                            "type": "log", "agent": "RAG-PLAYBOOK",
                            "message": f"✓ Top match: {top.get('playbook_id')} score={top.get('relevance_score')}",
                        }

                    # GTI tools — IoC enrichment
                    elif name == "enrich_ip":
                        ioc_data["ips"].append(resp)
                        yield {"type": "state", "key": "ioc_data", "data": ioc_data}
                        yield {"type": "log", "agent": "THREAT-INTEL", "message": "✓ Enriched IP IoC."}
                    elif name == "enrich_hash":
                        ioc_data["hashes"].append(resp)
                        yield {"type": "state", "key": "ioc_data", "data": ioc_data}
                        yield {"type": "log", "agent": "THREAT-INTEL", "message": "✓ Enriched hash IoC."}
                    elif name == "enrich_domain":
                        ioc_data["domains"].append(resp)
                        yield {"type": "state", "key": "ioc_data", "data": ioc_data}
                        yield {"type": "log", "agent": "THREAT-INTEL", "message": "✓ Enriched domain IoC."}
                    elif name == "bulk_enrich_iocs":
                        bulk = resp.get("bulk_enrich_iocs", resp)
                        if "ips" in bulk:
                            ioc_data["ips"].extend(bulk["ips"])
                        if "hashes" in bulk:
                            ioc_data["hashes"].extend(bulk["hashes"])
                        if "domains" in bulk:
                            ioc_data["domains"].extend(bulk["domains"])
                        yield {"type": "state", "key": "ioc_data", "data": ioc_data}
                        yield {"type": "log", "agent": "THREAT-INTEL", "message": "✓ Enriched IoC(s) successfully."}

                    # SOAR execution tools
                    elif name == "trigger_playbook":
                        yield {"type": "log", "agent": "ACTION-EXEC", "message": f"✓ Playbook triggered · exec_id={str(resp.get('execution_id',''))[:20]}"}
                    elif name == "add_worknote":
                        yield {"type": "log", "agent": "ACTION-EXEC", "message": "✓ Audit worknote added to ServiceNow."}
                    elif name == "close_incident":
                        yield {"type": "log", "agent": "ACTION-EXEC", "message": "✓ Incident closed in ServiceNow."}
                    elif name == "update_case_status":
                        yield {"type": "log", "agent": "ACTION-EXEC", "message": "✓ Case status updated in SecOps to RESOLVED."}

                # ── Text responses — detect analysis JSON and HITL signal ─────
                elif part.text and part.text.strip():
                    text = part.text.strip()

                    # Check every text event for a CaseAnalysis JSON blob
                    # It can come from GeminiAnalysisAgent or SOCOrchestrator
                    if author in ("SOCORCHESTRATOR", "GEMINIANALYSISAGENT"):
                        extracted = _extract_json(text)
                        if extracted and "recommended_playbook_id" in extracted and "case_summary" in extracted:
                            yield {"type": "state", "key": "analysis", "data": extracted}
                            conf = extracted.get("confidence_score", 0)
                            yield {"type": "step", "step": 6}
                            yield {
                                "type": "log", "agent": "GEMINI",
                                "message": f"✓ Analysis complete · confidence={conf * 100:.0f}%",
                            }

                        # HITL signal — pipeline pauses here
                        if "AWAITING_HITL_APPROVAL" in text:
                            severity = case_data["raw_case"].get("severity", "HIGH").upper()
                            conf = 0
                            # Try to get conf from already-extracted analysis
                            session = await _session_service.get_session(
                                app_name="sentinel-soc",
                                user_id=analyst_name,
                                session_id=session_id,
                            )
                            if session:
                                raw_analysis = session.state.get("case_analysis", {})
                                if isinstance(raw_analysis, dict):
                                    conf = raw_analysis.get("confidence_score", 0)
                                elif isinstance(raw_analysis, str):
                                    parsed = _extract_json(raw_analysis)
                                    conf = parsed.get("confidence_score", 0) if parsed else 0

                            if severity in ["LOW", "MEDIUM"] and conf >= 0.85:
                                yield {
                                    "type": "log", "agent": "ORCHESTRATOR",
                                    "message": f"Auto-remediating {severity} severity (confidence={conf * 100:.0f}%)",
                                }
                                yield {"type": "hitl", "state": "auto_approved"}
                            else:
                                yield {
                                    "type": "log", "agent": "ORCHESTRATOR",
                                    "message": f"Recommendation ready — awaiting HITL approval ({severity}, {conf * 100:.0f}% confidence)",
                                }
                                yield {"type": "hitl", "state": "awaiting"}
                            return

                        # Log non-JSON orchestrator thoughts (intermediate reasoning)
                        if not _extract_json(text) and "AWAITING" not in text and "transfer" not in text.lower():
                            yield {"type": "log", "agent": author, "message": text[:300]}

    except Exception as e:
        err_msg = str(e)
        if "429" in err_msg or "RESOURCE_EXHAUSTED" in err_msg:
            yield {
                "type": "log", "agent": "SYSTEM",
                "message": "⚠️ Vertex AI rate limit (429). Wait 60s and retry.",
            }
        else:
            yield {"type": "log", "agent": "SYSTEM", "message": f"⚠️ Pipeline Error: {err_msg[:200]}"}

    # ── Post-loop fallback ────────────────────────────────────────────────────
    # The orchestrator may end the event stream without emitting
    # AWAITING_HITL_APPROVAL as text (it writes case_analysis to session state
    # via output_key but stays silent). Check session state directly and emit
    # the HITL signal if analysis is present but HITL was never triggered.
    try:
        session = await _session_service.get_session(
            app_name="sentinel-soc",
            user_id=analyst_name,
            session_id=session_id,
        )
        if session:
            raw_analysis = session.state.get("case_analysis")
            if raw_analysis:
                # Parse if stored as string (output_key stores text output)
                analysis_dict = None
                if isinstance(raw_analysis, dict):
                    analysis_dict = raw_analysis
                elif isinstance(raw_analysis, str):
                    analysis_dict = _extract_json(raw_analysis)

                if analysis_dict and "recommended_playbook_id" in analysis_dict:
                    # Push to UI state if not already there
                    yield {"type": "state", "key": "analysis", "data": analysis_dict}
                    conf = analysis_dict.get("confidence_score", 0)
                    yield {"type": "step", "step": 6}
                    yield {
                        "type": "log", "agent": "GEMINI",
                        "message": f"✓ Analysis finalised from session state · confidence={conf * 100:.0f}%",
                    }
                    severity = case_data["raw_case"].get("severity", "HIGH").upper()
                    if severity in ["LOW", "MEDIUM"] and conf >= 0.85:
                        yield {
                            "type": "log", "agent": "ORCHESTRATOR",
                            "message": f"Auto-remediating {severity} severity (confidence={conf * 100:.0f}%)",
                        }
                        yield {"type": "hitl", "state": "auto_approved"}
                    else:
                        yield {
                            "type": "log", "agent": "ORCHESTRATOR",
                            "message": f"Recommendation ready — awaiting HITL approval ({severity}, {conf * 100:.0f}% confidence)",
                        }
                        yield {"type": "hitl", "state": "awaiting"}
    except Exception:
        pass  # Fallback failed silently — UI will show stuck state


async def resume_adk_pipeline(
    session_id: str,
    analyst_name: str,
    decision: str,
    analysis: dict,
    case_id: str,
    override_playbook: str | None = None,
    feedback: str | None = None,
):
    """
    Resume the pipeline after a HITL decision.
    Sends a follow-up message to the same session — ADK retains full
    conversation history and session state so the orchestrator can
    delegate to ActionExecutorAgent with full context.
    """
    runner = Runner(
        app_name="sentinel-soc",
        agent=soc_orchestrator,
        session_service=_session_service,
    )

    raw_case = _load_case_data(case_id)
    snow_ref = raw_case.get("snow_incident_ref", "INC0000000")

    if decision == "override":
        msg = (
            f"HITL APPROVAL RECEIVED. "
            f"ANALYST OVERRIDE: Use playbook {override_playbook} instead of the recommended one. "
            f"Please proceed with Action Execution using playbook_id={override_playbook} "
            f"and snow_incident_ref={snow_ref}."
        )
    elif decision == "reject":
        msg = (
            f"ANALYST FEEDBACK: {feedback} "
            f"Please re-delegate to GeminiAnalysisAgent to revise the analysis incorporating "
            f"this feedback, then output the revised CaseAnalysis JSON followed by AWAITING_HITL_APPROVAL."
        )
    else:  # Accepted
        playbook_id = analysis.get("recommended_playbook_id", "")
        msg = (
            f"HITL APPROVAL RECEIVED. "
            f"Proceed with Action Execution using playbook_id={playbook_id} "
            f"and snow_incident_ref={snow_ref}."
        )

    content = types.Content(role="user", parts=[types.Part.from_text(text=msg)])

    yield {"type": "log", "agent": "ORCHESTRATOR", "message": f"HITL: {decision} — resuming pipeline"}

    execution = {"execution": {"execution_id": "", "status": "", "action_steps": []}, "snow_ref": snow_ref}
    closure = {"snow_ref": snow_ref, "close_result": {}, "close_notes": "", "snow_state": {}}

    try:
        async for event in runner.run_async(
            session_id=session_id,
            user_id=analyst_name,
            new_message=content,
        ):
            author = event.author.upper() if event.author else "SYSTEM"

            if not event.content or not event.content.parts:
                continue

            for part in event.content.parts:

                if part.function_call:
                    name = part.function_call.name
                    if name != "transfer_to_agent":
                        yield {"type": "log", "agent": author, "message": f"→ invoking tool: {name}(...)"}

                elif part.function_response:
                    name = part.function_response.name
                    try:
                        resp = dict(part.function_response.response)
                    except Exception:
                        resp = {}

                    if name == "trigger_playbook":
                        execution["execution"] = resp
                        yield {"type": "state", "key": "execution", "data": execution}
                        yield {
                            "type": "log", "agent": "ACTION-EXEC",
                            "message": f"✓ Playbook triggered · exec_id={str(resp.get('execution_id', ''))[:20]}",
                        }
                    elif name == "add_worknote":
                        yield {"type": "log", "agent": "ACTION-EXEC", "message": "✓ Audit worknote added to ServiceNow."}
                    elif name == "close_incident":
                        closure["close_result"] = resp
                        closure["close_notes"] = resp.get("close_notes", "")
                        # Load updated SNOW state for the UI closure card
                        try:
                            from sentinel.tools.snow_mcp import get_incident_state
                            closure["snow_state"] = get_incident_state(snow_ref)
                        except Exception:
                            closure["snow_state"] = {}
                        yield {"type": "state", "key": "closure", "data": closure}
                        yield {"type": "log", "agent": "ACTION-EXEC", "message": "✓ Incident closed in ServiceNow."}
                    elif name == "update_case_status":
                        yield {"type": "log", "agent": "ACTION-EXEC", "message": "✓ Case status updated in SecOps to RESOLVED."}

                elif part.text and part.text.strip():
                    text = part.text.strip()
                    author_name = event.author if event.author else "SYSTEM"

                    # Re-analysis JSON after reject/override
                    if author in ("SOCORCHESTRATOR", "GEMINIANALYSISAGENT"):
                        extracted = None
                        try:
                            extracted = json.loads(text)
                        except json.JSONDecodeError:
                            match = re.search(r'\{.*\}', text, re.DOTALL)
                            if match:
                                try:
                                    extracted = json.loads(match.group())
                                except Exception:
                                    pass

                        if extracted and "recommended_playbook_id" in extracted and "case_summary" in extracted:
                            yield {"type": "state", "key": "analysis", "data": extracted}
                            conf = extracted.get("confidence_score", 0)
                            yield {"type": "log", "agent": "GEMINI", "message": f"✓ Re-analysis complete · confidence={conf * 100:.0f}%"}

                        if "AWAITING_HITL_APPROVAL" in text:
                            yield {"type": "log", "agent": "ORCHESTRATOR", "message": "Revised recommendation ready — awaiting HITL approval"}
                            yield {"type": "hitl", "state": "awaiting"}
                            return

    except Exception as e:
        err_msg = str(e)
        yield {"type": "log", "agent": "SYSTEM", "message": f"⚠️ Resume Error: {err_msg[:200]}"}

    if execution["execution"].get("execution_id"):
        yield {"type": "finish"}