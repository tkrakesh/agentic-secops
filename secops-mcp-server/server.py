"""
SecOps MCP Server — Cloud Run

Wraps the Agentic SecOps fixture data and exposes it via the MCP protocol
using Streamable HTTP transport. Designed for stateless Cloud Run deployment.

In production, replace the fixture data loading with real Google SecOps API calls.
"""
import asyncio
import contextlib
import json
import logging
import os
from pathlib import Path

import anyio
import uvicorn
from mcp import types as mcp_types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.responses import JSONResponse
from starlette.requests import Request

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Data directories ────────────────────────────────────────────────────────────
DATA_DIR = Path(__file__).parent / "data"
CASES_DIR = DATA_DIR / "cases"
SOAR_FILE = DATA_DIR / "soar_actions.json"

_case_cache: dict = {}
_soar_cache: dict = {}


def _load_case(case_id: str) -> dict:
    key = case_id.upper()
    if key not in _case_cache:
        path = CASES_DIR / f"{case_id.lower().replace('-', '_')}.json"
        if not path.exists():
            return {"error": f"Case {case_id} not found. Available: case_001, case_002"}
        _case_cache[key] = json.loads(path.read_text(encoding="utf-8"))
    return _case_cache[key]


def _load_soar() -> dict:
    global _soar_cache
    if not _soar_cache and SOAR_FILE.exists():
        _soar_cache = json.loads(SOAR_FILE.read_text(encoding="utf-8"))
    return _soar_cache


# ── Tool definitions ────────────────────────────────────────────────────────────
TOOLS = [
    mcp_types.Tool(
        name="get_case",
        description=(
            "Retrieve full case details from Google SecOps SIEM by case ID. "
            "Returns case metadata, severity, status, IoC list, and timeline."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "string",
                    "description": "The SecOps case identifier, e.g. CASE-001",
                }
            },
            "required": ["case_id"],
        },
    ),
    mcp_types.Tool(
        name="list_alerts",
        description=(
            "List all security alerts associated with a SecOps case. "
            "Returns alert rule names, severities, source/destination IPs, and timestamps."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "case_id": {"type": "string", "description": "The SecOps case identifier"}
            },
            "required": ["case_id"],
        },
    ),
    mcp_types.Tool(
        name="get_raw_logs",
        description=(
            "Retrieve raw CEF-format syslog entries associated with a SecOps case. "
            "Returns the full log text from the SIEM."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "case_id": {"type": "string", "description": "The SecOps case identifier"}
            },
            "required": ["case_id"],
        },
    ),
    mcp_types.Tool(
        name="get_affected_assets",
        description=(
            "Get all affected assets (endpoints, users, IPs) for a SecOps case. "
            "Returns hostname, IP, OS, user, and role for each affected asset."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "case_id": {"type": "string", "description": "The SecOps case identifier"}
            },
            "required": ["case_id"],
        },
    ),
    mcp_types.Tool(
        name="trigger_playbook",
        description=(
            "Trigger a SOAR playbook execution for a given case. "
            "Returns an execution_id and the list of action steps initiated."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "playbook_id": {
                    "type": "string",
                    "description": "The playbook identifier to execute, e.g. PB-003",
                },
                "case_id": {
                    "type": "string",
                    "description": "The SecOps case to run the playbook against",
                },
            },
            "required": ["playbook_id", "case_id"],
        },
    ),
    mcp_types.Tool(
        name="update_case_status",
        description=(
            "Update the resolution status of a SecOps case. "
            "Use this to mark cases as RESOLVED or CLOSED after playbook execution."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "case_id": {"type": "string", "description": "The SecOps case identifier"},
                "status": {
                    "type": "string",
                    "description": "New status, e.g. RESOLVED, CLOSED",
                },
                "notes": {"type": "string", "description": "Resolution notes to attach"},
            },
            "required": ["case_id", "status", "notes"],
        },
    ),
]


# ── Tool handler ────────────────────────────────────────────────────────────────
def _handle_tool(name: str, args: dict) -> dict | list | str:
    logger.info("Tool called: %s %s", name, args)

    if name == "get_case":
        case = _load_case(args["case_id"])
        if "error" in case:
            return case
        return {
            k: case[k]
            for k in [
                "case_id", "title", "severity", "status", "created_at",
                "source_system", "description", "alert_count",
                "affected_asset_count", "snow_incident_ref", "iocs", "timeline",
            ]
            if k in case
        }

    elif name == "list_alerts":
        return _load_case(args["case_id"]).get("alerts", [])

    elif name == "get_raw_logs":
        fname = args["case_id"].lower().replace("-", "_") + "_logs.txt"
        log_file = CASES_DIR / fname
        if log_file.exists():
            return log_file.read_text(encoding="utf-8")
        return f"No log fixture found for {args['case_id']}"

    elif name == "get_affected_assets":
        return _load_case(args["case_id"]).get("affected_assets", [])

    elif name == "trigger_playbook":
        soar = _load_soar()
        actions = soar.get("playbook_actions", {}).get(args["playbook_id"], [])
        exec_id = f"EXEC-{args['playbook_id']}-{args['case_id']}-DEMO"
        return {
            "execution_id": exec_id,
            "playbook_id": args["playbook_id"],
            "case_id": args["case_id"],
            "status": "initiated",
            "action_steps": actions,
            "message": (
                f"Playbook {args['playbook_id']} initiated successfully "
                f"for case {args['case_id']}"
            ),
        }

    elif name == "update_case_status":
        return {
            "case_id": args["case_id"],
            "updated_status": args["status"],
            "notes_added": True,
            "message": f"Case {args['case_id']} status updated to {args['status']}",
        }

    return {"error": f"Unknown tool: {name}"}


# ── MCP Server ──────────────────────────────────────────────────────────────────
mcp_server = Server("agentic-secops-mcp")


@mcp_server.list_tools()
async def list_tools() -> list[mcp_types.Tool]:
    return TOOLS


@mcp_server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[mcp_types.Content]:
    result = _handle_tool(name, arguments)
    text = json.dumps(result, indent=2) if isinstance(result, (dict, list)) else str(result)
    return [mcp_types.TextContent(type="text", text=text)]


# ── Streamable HTTP app (stateless — Cloud Run compatible) ──────────────────────
@contextlib.asynccontextmanager
async def lifespan(app: Starlette):
    async with session_manager.run():
        logger.info("Agentic SecOps MCP server started")
        yield
    logger.info("Agentic SecOps MCP server stopped")


session_manager = StreamableHTTPSessionManager(
    app=mcp_server,
    event_store=None,
    json_response=True,
    stateless=True,
)


async def handle_mcp(scope, receive, send):
    await session_manager.handle_request(scope, receive, send)


async def health_check(request: Request):
    return JSONResponse({"status": "ok", "server": "agentic-secops-mcp", "tools": len(TOOLS)})


starlette_app = Starlette(
    lifespan=lifespan,
    routes=[
        Mount("/mcp", app=handle_mcp),
    ],
)
starlette_app.add_route("/health", health_check, methods=["GET"])


# ── Entry point ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    logger.info("Starting SecOps MCP server on port %d", port)
    uvicorn.run(starlette_app, host="0.0.0.0", port=port, log_level="info")
