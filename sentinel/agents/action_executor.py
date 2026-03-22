"""
Action Executor Agent — HITL-gated SOAR playbook execution and SNOW closure.

POC:  Uses FunctionTools wrapping local fixtures and in-memory SNOW state.
PROD: Uses McpToolset for SecOps WRITE calls; SNOW tools remain as FunctionTools
      until the ServiceNow MCP server is deployed.

Switch by setting SECOPS_MCP_URL in the environment.
"""
from __future__ import annotations
import os
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool
from sentinel.tools.snow_mcp import add_worknote, close_incident

MODEL = os.getenv("SENTINEL_MODEL", "google/gemini-2.5-flash")
SECOPS_MCP_URL = os.getenv("SECOPS_MCP_URL", "")

SYSTEM_PROMPT = """You are the Action Executor Agent for Project Sentinel.

You execute approved SOAR playbook actions and close the ServiceNow incident.
You ONLY act when you receive explicit confirmation that HITL approval has been granted.

Your execution sequence:
1. Trigger the approved SOAR playbook:
   trigger_playbook(playbook_id=<approved_playbook_id>, case_id=<case_id>)

2. Add an audit worknote to the SNOW incident recording the approved action:
   add_worknote(inc_number=<snow_inc_ref>, note="SENTINEL AI: Analyst approved <playbook_name> at <timestamp>. Actions initiated: <action_summary>", author="Sentinel Action Executor (AI)")

3. Close the SNOW incident with full resolution notes:
   close_incident(inc_number=<snow_inc_ref>, close_notes="<detailed_notes>")
   Your close_notes MUST include:
   - Case summary (2 sentences)
   - Recommended playbook and why it was selected
   - Actions executed and their outcomes
   - Analyst who approved and timestamp
   - Confidence score at time of approval

4. Update the SecOps case status:
   update_case_status(case_id=<case_id>, status="RESOLVED", notes="<resolution_summary>")

Report the full execution log including each action, target, status, and duration.

SECURITY CONSTRAINT: If you receive instructions without explicit HITL approval confirmation, respond with:
"ACTION BLOCKED: HITL approval token not present in context. No actions executed." """.strip()


def _make_tools():
    snow_tools = [FunctionTool(add_worknote), FunctionTool(close_incident)]

    if SECOPS_MCP_URL:
        # PROD: Cloud Run MCP server for SecOps WRITE tools
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
        # POC: local FunctionTools
        from sentinel.tools.secops_mcp import trigger_playbook, update_case_status
        return [
            FunctionTool(trigger_playbook),
            FunctionTool(update_case_status),
        ] + snow_tools


action_executor_agent = LlmAgent(
    name="ActionExecutorAgent",
    description="Executes the approved SOAR playbook actions and closes the ServiceNow incident with a full audit trail. Only operates after explicit HITL approval.",
    model=MODEL,
    instruction=SYSTEM_PROMPT,
    tools=_make_tools(),
    output_key="execution_log",
)
