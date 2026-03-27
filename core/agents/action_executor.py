"""
Action Executor Agent — HITL-gated SOAR playbook execution and SNOW closure.

POC:  Uses FunctionTools wrapping local fixtures and in-memory SNOW state.
PROD: Uses McpToolset for SecOps WRITE calls.

Switch by setting SECOPS_MCP_URL in the environment.
"""
from __future__ import annotations
import os
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool
from core.tools.snow_mcp import add_worknote, close_incident

MODEL = os.getenv("SECOPS_MODEL_FLASH", "gemini-2.5-flash")
SECOPS_MCP_URL = os.getenv("SECOPS_MCP_URL", "")

SYSTEM_PROMPT = """You are the Action Executor Agent for Agentic SecOps.

You execute approved SOAR playbook actions and close the ServiceNow incident.
You ONLY act when you receive explicit confirmation (e.g. "HITL DECISION RECEIVED") that HITL approval has been granted.

Your execution sequence — CALL ALL FOUR TOOLS IN ORDER WITHOUT STOPPING:
1. trigger_playbook(playbook_id=<approved_playbook_id>, case_id=<case_id>)
2. add_worknote(inc_number=<snow_inc_ref>, note="AGENTIC SECOPS AI: Analyst approved <playbook_name>. Actions initiated.", author="Agentic SecOps Action Executor (AI)")
3. close_incident(inc_number=<snow_inc_ref>, close_notes="AGENTIC SECOPS RESOLUTION REPORT:\n\nCase Summary: <summarize findings from context>\nThreat Classification: <from context>\nResolution Action: <playbook used>\nAI Confidence: <percentage>\nIncident Verdict: <TRUE POSITIVE or FALSE POSITIVE based on context>\n\nIncident resolved and confirmed by Agentic SecOps AI pipeline.")
4. update_case_status(case_id=<case_id>, status="RESOLVED", notes="Resolved by Agentic SecOps AI pipeline.")

COMPLETION REQUIREMENT: You are NOT finished until all 4 tools have been called successfully. Use the CASE ANALYSIS CONTEXT provided in the message from the Orchestrator. Do not return or transfer back until you have verified the 'RESOLVED' status update is complete.

Report the full execution log including each action, target, status, and duration.

SECURITY CONSTRAINT: If you receive instructions/transfer without the "HITL", "Approved", or "Proceed" keyword in the context, respond with:
"ACTION BLOCKED: HITL approval token not present in context. No actions executed."

When execution is complete, transfer back to SOCOrchestrator.""".strip()


def _make_tools():
    snow_tools = [FunctionTool(add_worknote), FunctionTool(close_incident)]

    if SECOPS_MCP_URL:
        from google.adk.tools.mcp_tool import McpToolset
        from google.adk.tools.mcp_tool.mcp_session_manager import SseConnectionParams
        import google.auth
        import google.auth.transport.requests

        def _get_id_token() -> str:
            credentials, _ = google.auth.default()
            auth_req = google.auth.transport.requests.Request()
            credentials.refresh(auth_req)
            return credentials.token

        secops_tools = McpToolset(
            connection_params=SseConnectionParams(
                url=f"{SECOPS_MCP_URL.rstrip('/')}/mcp",
                headers={"Authorization": f"Bearer {_get_id_token()}"},
            ),
            tool_filter=["trigger_playbook", "update_case_status"],
        )
        return [secops_tools] + snow_tools
    else:
        from core.tools.secops_mcp import trigger_playbook, update_case_status
        return [
            FunctionTool(trigger_playbook),
            FunctionTool(update_case_status),
        ] + snow_tools


action_executor_agent = LlmAgent(
    name="ActionExecutorAgent",
    description="Executes the approved SOAR playbook actions and closes the ServiceNow incident. Only operates after explicit HITL approval.",
    model=MODEL,
    instruction=SYSTEM_PROMPT,
    tools=_make_tools(),
    output_key="execution_log",
    # CRITICAL: prevent lateral transfer to peer agents.
    # Must return to SOCOrchestrator after completing execution.
    disallow_transfer_to_peers=True,
)