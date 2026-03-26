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

# Agents mapping for log consistency
AGENT_MAP = {
    "SOCORCHESTRATOR": "SOCOrchestrator",
    "ENRICHMENTAGENT": "EnrichmentAgent",
    "THREATANALYSTAGENT": "ThreatAnalystAgent",
    "ACTIONEXECUTORAGENT": "ActionExecutorAgent",
    # Legacy / Fallback mapping
    "ORCHESTRATOR": "SOCOrchestrator",
    "ENRICHMENT": "EnrichmentAgent",
    "AGENT": "ThreatAnalystAgent",
    "ANALYSISAGENT": "ThreatAnalystAgent",
    "GEMINIANALYSISAGENT": "ThreatAnalystAgent",
    "ACTION-EXEC": "ActionExecutorAgent",
    "SYSTEM": "Agentic SecOps System"
}

def _get_agent_name(raw_name: str) -> str:
    """Standardize agent names for professional logging."""
    if not raw_name: return "Agentic SecOps"
    n = raw_name.upper()
    return AGENT_MAP.get(n, n.capitalize())

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from sentinel.agents.orchestrator import soc_orchestrator
from sentinel.agents.chat_agent import soc_chat_agent

async def run_soc_chat(user_input: str, session_id: str, analyst_name: str, service: InMemorySessionService):
    """Run a single conversational turn with the SOC Chat Agent."""
    runner = Runner(
        app_name="sentinel-soc",
        agent=soc_chat_agent,
        session_service=service
    )
    content = types.Content(role="user", parts=[types.Part.from_text(text=user_input)])
    async for event in runner.run_async(
        session_id=session_id,
        user_id=analyst_name,
        new_message=content
    ):
        if hasattr(event, "text"):
            yield {"type": "text", "text": event.text}

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

def _check_auto_approve(case_id, analysis_data, case_data):
    """Unified logic for agent-driven and policy-based auto-approval."""
    agent_recommends = analysis_data.get("recommend_auto_approval", False)
    
    analysis_sev = analysis_data.get("severity", "").upper()
    raw_sev = case_data["raw_case"].get("severity", "HIGH").upper()
    current_sev = (analysis_sev or raw_sev)
    confidence = analysis_data.get("confidence_score", 0)
    
    # User Policy: Auto-remediate if severity is MEDIUM or LOW and confidence > 90%.
    # Also auto-approve specific low-risk administrative cases (CASE-006/009).
    should_auto = (("LOW" in current_sev or "MEDIUM" in current_sev) and confidence >= 0.90) or (case_id in ["CASE-006", "CASE-009"])
    return should_auto, current_sev, analysis_data.get("reasoning_for_recommendation", "N/A")

async def run_adk_pipeline(
    case_id: str,
    session_id: str,
    analyst_name: str,
    session_service: InMemorySessionService,
    yield_delay: float = 0.05,
):
    """
    Run the full SOC analysis pipeline via the SOCOrchestrator root agent.
    """
    runner = Runner(
        app_name="sentinel-soc",
        agent=soc_orchestrator,
        session_service=session_service,
    )

    await session_service.create_session(
        state={"case_id": case_id},
        app_name="sentinel-soc",
        user_id=analyst_name,
        session_id=session_id,
    )

    yield {"type": "log", "agent": "ORCHESTRATOR", "message": f"Pipeline initiated for {case_id}"}
    yield {"type": "step", "step": 1}
    yield {"type": "active_steps", "steps": {1}}

    case_data = {
        "case": {}, "alerts": [], "logs": "",
        "assets": [], "raw_case": _load_case_data(case_id),
    }
    rag_results = []
    ioc_data = {"ips": [], "hashes": [], "domains": []}
    analysis_emitted = False
    hitl_emitted = False
    last_analysis_json = None

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
            author = _get_agent_name(event.author)
            ua = author.upper()
            if ua == "ENRICHMENTAGENT":
                # Enrichment spans Step 2, 3, 4. Show Step 2 as active during tool work.
                yield {"type": "step", "step": 2}
            elif ua == "THREATANALYSTAGENT":
                yield {"type": "step", "step": 5}
            elif ua == "SOCORCHESTRATOR" and not analysis_emitted:
                # Orchestrator start is Step 1 (Ingestion)
                yield {"type": "step", "step": 1}

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
                        from google.protobuf.json_format import MessageToDict
                        resp = MessageToDict(part.function_response.response._pb) if hasattr(part.function_response.response, "_pb") else dict(part.function_response.response)
                    except Exception as e:
                        yield {"type": "log", "agent": "SYSTEM", "message": f"⚠️ Proto parse fallback: {str(e)[:100]}"}
                        resp = dict(part.function_response.response) if hasattr(part.function_response.response, "items") else {}

                    if name == "run_parallel_enrichment":
                        data = resp.get("run_parallel_enrichment", resp)
                        if "secops_data" in data:
                            sd = data["secops_data"]; case_data["alerts"] = sd.get("alerts", []); case_data["assets"] = sd.get("assets", []); case_data["logs"] = sd.get("logs", "")
                            yield {"type": "state", "key": "case_data", "data": case_data}
                        if "rag_results" in data:
                            rag_results = data["rag_results"]; yield {"type": "state", "key": "rag_results", "data": rag_results}
                        if "ioc_enrichments" in data:
                            ioc_data = data["ioc_enrichments"]; yield {"type": "state", "key": "ioc_data", "data": ioc_data}
                        yield {"type": "log", "agent": "EnrichmentAgent", "message": "✓ Parallel enrichment complete."}

                    elif name == "trigger_playbook":
                        yield {"type": "log", "agent": "ActionExecutorAgent", "message": f"✓ Playbook triggered."}

                elif part.text and part.text.strip():
                    text = part.text.strip()
                    if ua in ("SOCORCHESTRATOR", "THREATANALYSTAGENT"):
                        extracted = _extract_json(text)
                        if extracted and "recommended_playbook_id" in extracted:
                            last_analysis_json = extracted
                            yield {"type": "state", "key": "analysis", "data": extracted}
                            if not analysis_emitted:
                                yield {"type": "step", "step": 6}
                                yield {"type": "log", "agent": "AGENT", "message": f"✓ Analysis complete."}
                                analysis_emitted = True

                        if "AWAITING_HITL_APPROVAL" in text and not hitl_emitted:
                            hitl_emitted = True
                            should_auto, current_sev, reasoning = _check_auto_approve(case_id, last_analysis_json or {}, case_data)
                            
                            if should_auto:
                                msg = f"✓ Auto-approving recommendation. Agent reasoning: {reasoning}"
                                yield {"type": "log", "agent": "ORCHESTRATOR", "message": msg}
                                yield {"type": "hitl", "state": "auto_approved"}
                            else:
                                yield {"type": "log", "agent": "ORCHESTRATOR", "message": f"Recommendation ready — awaiting HITL approval ({current_sev})"}
                                yield {"type": "hitl", "state": "awaiting"}
                            return

                        if not extracted and "AWAITING" not in text and "transfer" not in text.lower():
                            if "[RUNNING:STEP:" in text:
                                m = re.search(r"\[RUNNING:STEP:(\d+)\]", text)
                                if m: yield {"type": "active_step_add", "step": int(m.group(1))}
                            elif "[DONE:STEP:" in text:
                                m = re.search(r"\[DONE:STEP:(\d+)\]", text)
                                if m: yield {"type": "active_step_remove", "step": int(m.group(1))}
                            yield {"type": "log", "agent": author, "message": text[:300]}
    except Exception as e:
        yield {"type": "log", "agent": "SYSTEM", "message": f"⚠️ Pipeline Error: {str(e)[:200]}"}

    # Fallback to check session state for analysis if stream ended early
    if not hitl_emitted:
        session = await session_service.get_session(app_name="sentinel-soc", user_id=analyst_name, session_id=session_id)
        raw_analysis = session.state.get("case_analysis")
        if session and raw_analysis:
            # ADK session state stores raw agent output (string), must extract as dict for UI
            data = _extract_json(raw_analysis) if isinstance(raw_analysis, str) else raw_analysis
            if data:
                yield {"type": "state", "key": "analysis", "data": data}
                yield {"type": "step", "step": 6}
                should_auto, current_sev, reasoning = _check_auto_approve(case_id, data, case_data)
                if should_auto:
                    msg = f"✓ Auto-approving recommendation. Agent reasoning: {reasoning}"
                    yield {"type": "log", "agent": "ORCHESTRATOR", "message": msg}
                    yield {"type": "hitl", "state": "auto_approved"}
                else:
                    yield {"type": "hitl", "state": "awaiting"}
            else:
                yield {"type": "hitl", "state": "awaiting"}
        else:
            yield {"type": "hitl", "state": "awaiting"}

async def resume_adk_pipeline(
    session_id: str,
    analyst_name: str,
    decision: str,
    analysis: dict,
    case_id: str,
    session_service: InMemorySessionService,
    override_playbook: str | None = None,
    feedback: str | None = None,
):
    """
    Resume the pipeline after a HITL decision.
    Bypasses the Orchestrator to avoid loops and resumes directly with ActionExecutorAgent.
    """
    yield {"type": "log", "agent": "SYSTEM", "message": f"DEBUG: Entering resume_adk_pipeline with decision: {decision}"}
    from sentinel.agents.action_executor import action_executor_agent
    runner = Runner(
        app_name="sentinel-soc",
        agent=action_executor_agent,
        session_service=session_service,
    )

    raw_case = _load_case_data(case_id)
    snow_ref = raw_case.get("snow_incident_ref", "INC0000000")
    if decision in ("Accepted", "Auto-Approved"):
        msg = f"HITL DECISION RECEIVED: Analyst {analyst_name} has ACCEPTED recommendation.\nApproved playbook: {analysis.get('recommended_playbook_id')}.\nServiceNow Incident: {snow_ref}.\nActionExecutorAgent: proceed with Step 8 execution now."
    elif decision == "override":
        msg = f"HITL DECISION RECEIVED: Analyst {analyst_name} has OVERRIDDEN with playbook {override_playbook}.\nServiceNow Incident: {snow_ref}.\nActionExecutorAgent: execute the override playbook now."
    else:  # reject
        msg = f"HITL DECISION RECEIVED: Analyst {analyst_name} REJECTED recommendation.\nFeedback: {feedback}\nPlease revise the analysis and wait for approval again."

    content = types.Content(role="user", parts=[types.Part.from_text(text=msg)])
    yield {"type": "log", "agent": "ORCHESTRATOR", "message": f"▶ Executing {decision} decision — delegating to ActionExecutorAgent"}

    execution = {"execution": {"execution_id": "", "status": "", "action_steps": []}, "snow_ref": snow_ref}
    closure = {"snow_ref": snow_ref, "close_result": {}, "close_notes": "", "snow_state": {}}

    try:
        async for event in runner.run_async(
            session_id=session_id,
            user_id=analyst_name,
            new_message=content,
        ):
            author = _get_agent_name(event.author)
            ua = author.upper()
            if not event.content or not event.content.parts: continue

            for part in event.content.parts:
                if part.function_call:
                    name = part.function_call.name
                    if name != "transfer_to_agent":
                        yield {"type": "log", "agent": author, "message": f"→ invoking tool: {name}(...)"}

                elif part.function_response:
                    name = part.function_response.name
                    resp = dict(part.function_response.response) if hasattr(part.function_response.response, "items") else {}

                    if name == "trigger_playbook":
                        execution["execution"] = resp
                        yield {"type": "step", "step": 7}
                        yield {"type": "state", "key": "execution", "data": execution}
                        yield {"type": "log", "agent": "ActionExecutorAgent", "message": f"✓ Playbook triggered."}
                    elif name == "add_worknote":
                        yield {"type": "log", "agent": "ActionExecutorAgent", "message": "✓ Audit worknote added to ServiceNow (Agentic SecOps)."}
                    elif name == "close_incident":
                        closure["close_result"] = resp
                        closure["close_notes"] = resp.get("close_notes", "")
                        try:
                            from sentinel.tools.snow_mcp import get_incident_state
                            closure["snow_state"] = get_incident_state(snow_ref)
                        except Exception: pass
                        yield {"type": "step", "step": 8}
                        yield {"type": "state", "key": "closure", "data": closure}
                        yield {"type": "log", "agent": "ActionExecutorAgent", "message": "✓ Incident closed in ServiceNow."}
                    elif name == "update_case_status":
                        yield {"type": "log", "agent": "ActionExecutorAgent", "message": "✓ Case status updated in SecOps to RESOLVED."}

                elif part.text and part.text.strip():
                    text = part.text.strip()
                    if ua in ("SOCORCHESTRATOR", "THREATANALYSTAGENT"):
                        extracted = _extract_json(text)
                        if extracted and "recommended_playbook_id" in extracted:
                            yield {"type": "state", "key": "analysis", "data": extracted}
                            yield {"type": "log", "agent": "ThreatAnalystAgent", "message": "✓ Re-analysis complete."}
                        # In resume mode, we don't want to revert to hitl: awaiting 
                        # unless the agent expressly says so via a specific tool or rejection flow.
                        pass
    except Exception as e:
        yield {"type": "log", "agent": "SYSTEM", "message": f"⚠️ Resume Error: {str(e)[:200]}"}

    if execution["execution"].get("execution_id") or closure["close_result"]:
        yield {"type": "finish"}