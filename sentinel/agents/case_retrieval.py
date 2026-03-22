"""
Case Retrieval Agent — fetches and structures full case data.

POC:  Uses FunctionTools wrapping local fixture data.
PROD: Uses McpToolset connecting to the sentinel-secops-mcp Cloud Run MCP server.

Switch between modes by setting SECOPS_MCP_URL in the environment:
  - Unset / empty  → POC mode (FunctionTools, local fixtures)
  - Set to a URL   → PROD mode (McpToolset, Cloud Run MCP server)
"""
from __future__ import annotations
import os
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

MODEL = os.getenv("SENTINEL_MODEL", "google/gemini-2.5-flash")
SECOPS_MCP_URL = os.getenv("SECOPS_MCP_URL", "")

SYSTEM_PROMPT = """You are the Case Retrieval Agent for Project Sentinel, a SOC AIOps platform.

Your sole responsibility is to fetch complete case data from Google SecOps and structure it clearly.

When given a case_id, you MUST call ALL of these tools in order:
1. get_case(case_id) — get the case overview
2. list_alerts(case_id) — get all associated alerts
3. get_raw_logs(case_id) — get the raw CEF log entries
4. get_affected_assets(case_id) — get the asset inventory

After calling all tools, produce a structured summary with these sections:
- CASE OVERVIEW: case_id, title, severity, created_at, description
- ALERTS: numbered list of all alerts with rule_name, severity, source_ip, timestamp
- AFFECTED ASSETS: table of hostname, IP, OS, user, role
- IOCs IDENTIFIED: list all IPs, file hashes, and domains from the case
- RAW LOG EXCERPT: first 5 log lines to give analysts a feel for the data

You are READ-ONLY. You NEVER modify or write to any system.""".strip()


def _make_tools():
    if SECOPS_MCP_URL:
        # PROD: Cloud Run MCP server
        from google.adk.tools.mcp_tool import McpToolset
        from google.adk.tools.mcp_tool.mcp_session_manager import SseConnectionParams
        import google.auth
        import google.auth.transport.requests

        def _get_id_token() -> str:
            """Get a Cloud Run identity token for authenticated MCP calls."""
            credentials, _ = google.auth.default()
            auth_req = google.auth.transport.requests.Request()
            credentials.refresh(auth_req)
            return credentials.token

        return [
            McpToolset(
                connection_params=SseConnectionParams(
                    url=f"{SECOPS_MCP_URL.rstrip('/')}/mcp",
                    headers={"Authorization": f"Bearer {_get_id_token()}"},
                ),
                tool_filter=["get_case", "list_alerts", "get_raw_logs", "get_affected_assets"],
            )
        ]
    else:
        # POC: local FunctionTools
        from sentinel.tools.secops_mcp import (
            get_case, list_alerts, get_raw_logs, get_affected_assets,
        )
        return [
            FunctionTool(get_case),
            FunctionTool(list_alerts),
            FunctionTool(get_raw_logs),
            FunctionTool(get_affected_assets),
        ]


case_retrieval_agent = LlmAgent(
    name="CaseRetrievalAgent",
    description="Fetches complete case data from Google SecOps SIEM including alerts, assets, raw logs, and IoC list.",
    model=MODEL,
    instruction=SYSTEM_PROMPT,
    tools=_make_tools(),
    output_key="case_context",
)
