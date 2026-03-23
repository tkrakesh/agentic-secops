"""
runner.py — ADK pipeline runner for Streamlit.

Refactored to use native Google ADK Multi-Agent Orchestration.
The Runner executes the SOCOrchestrator, and we intercept the ADK Event
stream to populate the structured dictionaries the Streamlit UI expects.
"""

from __future__ import annotations
import json
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

# Global session service to retain state across Streamlit UI re-runs
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

async def run_adk_pipeline(case_id: str, session_id: str, analyst_name: str, yield_delay: float = 0.1):
    """
    Starts the ADK agentic pipeline.
    Yields dicts describing UI updates based on the ADK event stream.
    """
    runner = Runner(
        app_name='sentinel-soc',
        agent=soc_orchestrator,
        session_service=_session_service,
    )
    
    query = f"Please analyse case {case_id} end-to-end following your pipeline sequence."
    
    # Create the session state
    session = await _session_service.create_session(
        state={'case_id': case_id}, app_name='sentinel-soc', user_id=analyst_name, session_id=session_id
    )
    
    yield {"type": "log", "agent": "ORCHESTRATOR", "message": f"Pipeline initiated for {case_id}"}
    yield {"type": "step", "step": 1}
    
    # We will build up state as tools return
    case_data = {"case": {}, "alerts": [], "logs": "", "assets": [], "raw_case": _load_case_data(case_id)}
    rag_results = []
    ioc_data = {"ips": [], "hashes": [], "domains": []}
    
    hit_hitl = False
    
    for attempt in range(5):
        content = types.Content(role='user', parts=[types.Part.from_text(text=query)])
        events_iter = runner.run_async(session_id=session_id, user_id=analyst_name, new_message=content)
        
        async for event in events_iter:
            author = event.author.upper() if event.author else "SYSTEM"
            
            # Determine the pipeline step roughly by author
            if author == "CASERETRIEVALAGENT": yield {"type": "step", "step": 2}
            elif author == "RAGPLAYBOOKAGENT": yield {"type": "step", "step": 3}
            elif author == "THREATINTELAGENT": yield {"type": "step", "step": 4}
            elif author == "SOCORCHESTRATOR": yield {"type": "step", "step": 5}
            
            if event.content and event.content.parts:
                for part in event.content.parts:
                    # Intercept Tool Calls (for logging)
                    if part.function_call:
                        name = part.function_call.name
                        args = dict(part.function_call.args) if part.function_call.args else {}
                        if name != "transfer_to_agent":
                            msg = f"→ invoking tool: {name}(...)"
                            yield {"type": "log", "agent": author, "message": msg}
                            await asyncio.sleep(yield_delay)
                    
                    # Intercept Tool Responses (to build UI state)
                    elif part.function_response:
                        name = part.function_response.name
                        
                        try:
                            from google.protobuf.json_format import MessageToDict
                            resp = MessageToDict(part.function_response.response._pb) if hasattr(part.function_response.response, "_pb") else dict(part.function_response.response)
                        except Exception:
                            resp = dict(part.function_response.response) if hasattr(part.function_response.response, "items") else part.function_response.response
                        
                        def unwrap_value(r, prefer_list=False):
                            if not isinstance(r, dict): 
                                return [r] if prefer_list and not isinstance(r, list) else r
                            for k in ["result", "value", "list", "items", "alerts", "assets", "logs", name]:
                                if k in r: 
                                    val = r[k]
                                    return [val] if prefer_list and not isinstance(val, list) else val
                            if len(r) == 1: 
                                val = list(r.values())[0]
                                return [val] if prefer_list and not isinstance(val, list) else val
                            return [r] if prefer_list else r

                        if name == "get_case": case_data["raw_case"] = resp
                        elif name == "list_alerts": case_data["alerts"] = unwrap_value(resp, True)
                        elif name == "get_raw_logs": case_data["logs"] = unwrap_value(resp, False)
                        elif name == "get_affected_assets": case_data["assets"] = unwrap_value(resp, True)
                        elif name == "query_playbook_corpus": 
                            lst = unwrap_value(resp, True)
                            if isinstance(lst, list): rag_results.extend(lst)
                        elif name == "enrich_ip": ioc_data["ips"].append(resp)
                        elif name == "enrich_hash": ioc_data["hashes"].append(resp)
                        elif name == "enrich_domain": ioc_data["domains"].append(resp)
                        
                        if name in ["get_affected_assets"]:
                            yield {"type": "state", "key": "case_data", "data": case_data}
                            yield {"type": "log", "agent": "CASE-RETRIEVAL", "message": f"✓ Fetched {len(case_data.get('alerts',[]))} alerts and {len(case_data.get('assets',[]))} assets."}
                        elif name == "query_playbook_corpus":
                            yield {"type": "state", "key": "rag_results", "data": rag_results}
                            top = rag_results[0] if rag_results else {}
                            yield {"type": "log", "agent": "RAG-PLAYBOOK", "message": f"✓ Top match: {top.get('playbook_id')} score={top.get('relevance_score')}"}
                        elif name in ["enrich_ip", "enrich_hash", "enrich_domain"]:
                            yield {"type": "state", "key": "ioc_data", "data": ioc_data}
                            yield {"type": "log", "agent": "THREAT-INTEL", "message": f"✓ Enriched IoC from {name}"}

                    # Agent textual responses
                    elif part.text:
                        # Check if this is the structured schema output from SOCOrchestrator
                        if author == "SOCORCHESTRATOR":
                            extracted_json = None
                            try:
                                extracted_json = json.loads(part.text)
                            except json.JSONDecodeError:
                                import re
                                match = re.search(r'\{.*\}', part.text, re.DOTALL)
                                if match:
                                    try:
                                        extracted_json = json.loads(match.group())
                                    except Exception:
                                        pass
                                        
                            if extracted_json and "recommended_playbook_id" in extracted_json:
                                # Also check if it's the actual outer JSON
                                if "case_summary" in extracted_json:
                                    yield {"type": "state", "key": "analysis", "data": extracted_json}
                                    conf = extracted_json.get("confidence_score", 0)
                                    yield {"type": "step", "step": 6}
                                    yield {"type": "log", "agent": "GEMINI", "message": f"✓ Analysis complete · confidence={conf*100:.0f}%"}
                                    
                                    # Trigger conditional HITL based on severity and confidence
                                    severity = case_data.get("raw_case", {}).get("severity", "HIGH").upper()
                                    if severity in ["LOW", "MEDIUM"] and conf >= 0.85:
                                        msg = f"Auto-remediating {severity} severity case (Confidence: {conf*100:.0f}%)"
                                        yield {"type": "log", "agent": "ORCHESTRATOR", "message": msg}
                                        yield {"type": "hitl", "state": "auto_approved"}
                                        hit_hitl = True
                                        return
                                    else:
                                        msg = f"Recommendation ready — awaiting HITL approval ({severity} severity, {conf*100:.0f}% confidence)"
                                        yield {"type": "log", "agent": "ORCHESTRATOR", "message": msg}
                                        yield {"type": "hitl", "state": "awaiting"}
                                        hit_hitl = True
                                        return
                                
                            # Fallback if it hits HITL keyword without proper JSON parsed
                            if "AWAITING_HITL_APPROVAL" in part.text:
                                yield {"type": "log", "agent": "ORCHESTRATOR", "message": "Recommendation ready — awaiting HITL approval"}
                                yield {"type": "hitl", "state": "awaiting"}
                                hit_hitl = True
                                return
                                
                            # Log intermediate thoughts if it's not JSON
                            if not extracted_json and "AWAITING" not in part.text:
                                msg = part.text.strip()
                                if msg: yield {"type": "log", "agent": "ORCHESTRATOR", "message": msg}

                        if "transfer" not in part.text.lower():
                            pass

        if hit_hitl:
            break
            
        yield {"type": "log", "agent": "SYSTEM", "message": f"Pipeline auto-resuming (Attempt {attempt+2}/5)..."}
        query = "Please continue where you left off. You MUST complete ALL 4 steps of the PIPELINE SEQUENCE and output the final CaseAnalysis JSON with 'AWAITING_HITL_APPROVAL'."


async def resume_adk_pipeline(session_id: str, analyst_name: str, decision: str, analysis: dict, case_id: str, override_playbook: str | None = None, feedback: str | None = None):
    """
    Resumes the ADK pipeline to handle HITL and execution.
    """
    runner = Runner(
        app_name='sentinel-soc',
        agent=soc_orchestrator,
        session_service=_session_service,
    )
    
    if decision == "override":
        msg = f"ANALYST OVERRIDE: The analyst rejected the initial playbook and explicitly selected playbook {override_playbook}. Please re-evaluate the case given this selection and output the new CaseAnalysis structured JSON."
    elif decision == "reject":
        msg = f"ANALYST FEEDBACK: {feedback}\nPlease incorporate this feedback, re-evaluate, and output the new CaseAnalysis structured JSON."
    else: # Accepted
        msg = "HITL APPROVAL RECEIVED. Please proceed with Action Execution."
        
    content = types.Content(role='user', parts=[types.Part.from_text(text=msg)])
    
    events_iter = runner.run_async(session_id=session_id, user_id=analyst_name, new_message=content)
    
    if decision != "Accepted":
        yield {"type": "log", "agent": "ORCHESTRATOR", "message": f"HITL: Processing {decision}..."}
        
    execution = {"execution": {"execution_id": "", "status": "", "action_steps": []}, "snow_ref": ""}
    closure = {"snow_ref": "", "close_result": {}, "close_notes": "", "snow_state": {}}
    
    # Inject snow ref for closure
    raw_case = _load_case_data(case_id)
    execution["snow_ref"] = raw_case.get("snow_incident_ref", "INC0000000")
    closure["snow_ref"] = execution["snow_ref"]
    
    async for event in events_iter:
        author = event.author.upper() if event.author else "SYSTEM"
        
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.function_call:
                    name = part.function_call.name
                    if name != "transfer_to_agent":
                        yield {"type": "log", "agent": author, "message": f"→ invoking tool: {name}(...)"}
                
                elif part.function_response:
                    name = part.function_response.name
                    resp = dict(part.function_response.response)
                    
                    if name == "trigger_playbook":
                        execution["execution"] = resp
                        yield {"type": "state", "key": "execution", "data": execution}
                        yield {"type": "log", "agent": "ACTION-EXEC", "message": f"✓ Playbook triggered · exec_id={resp.get('execution_id','')[:20]}"}
                    elif name == "add_worknote":
                        pass
                    elif name == "close_incident":
                        closure["close_result"] = resp
                        yield {"type": "state", "key": "closure", "data": closure}
                        yield {"type": "log", "agent": "ACTION-EXEC", "message": f"✓ Incident closed in ServiceNow."}
                    elif name == "update_case_status":
                        yield {"type": "log", "agent": "ACTION-EXEC", "message": f"✓ Case status updated in SecOps to RESOLVED."}
                        
                elif part.text:
                    if author == "SOCORCHESTRATOR":
                        extracted_json = None
                        try:
                            extracted_json = json.loads(part.text)
                        except json.JSONDecodeError:
                            import re
                            match = re.search(r'\{.*\}', part.text, re.DOTALL)
                            if match:
                                try:
                                    extracted_json = json.loads(match.group())
                                except Exception:
                                    pass
                                    
                        if extracted_json and "recommended_playbook_id" in extracted_json:
                            # Handle re-evaluation CaseAnalysis output
                            if "case_summary" in extracted_json:
                                yield {"type": "state", "key": "analysis", "data": extracted_json}
                                conf = extracted_json.get("confidence_score", 0)
                                yield {"type": "log", "agent": "GEMINI", "message": f"✓ Re-analysis complete · confidence={conf*100:.0f}%"}
                            
                        # If it hits HITL again after re-evaluation
                        if "AWAITING_HITL_APPROVAL" in part.text:
                            yield {"type": "log", "agent": "ORCHESTRATOR", "message": "Revised recommendation ready — awaiting HITL approval"}
                            yield {"type": "hitl", "state": "awaiting"}
                            return

    if execution["execution"].get("execution_id"):
        # Done Execution phase
        yield {"type": "finish"}

