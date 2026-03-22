"""
Mock SecOps MCP Server — Google ADK FunctionTools

Wraps fixture data to simulate Google SecOps SIEM/SOAR MCP calls.
In production, these are replaced by real SecOps MCP server connections.
"""

from __future__ import annotations
import json
import os
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
CASES_DIR = DATA_DIR / "cases"
SOAR_FILE = DATA_DIR / "soar_actions.json"

_case_cache: dict = {}
_soar_cache: dict = {}


def _load_case(case_id: str) -> dict:
    if case_id not in _case_cache:
        path = CASES_DIR / f"{case_id.lower().replace('-', '_')}.json"
        if not path.exists():
            raise FileNotFoundError(f"Case fixture not found: {path}")
        with open(path, encoding="utf-8") as f:
            _case_cache[case_id] = json.load(f)
    return _case_cache[case_id]


def _load_soar() -> dict:
    global _soar_cache
    if not _soar_cache:
        with open(SOAR_FILE, encoding="utf-8") as f:
            _soar_cache = json.load(f)
    return _soar_cache


# ── Tool Functions ─────────────────────────────────────────────────────────────

def get_case(case_id: str) -> dict:
    """Retrieve full case details from Google SecOps SIEM by case ID.

    Args:
        case_id: The SecOps case identifier (e.g. CASE-001)

    Returns:
        Complete case data including alerts, assets, IoCs, and timeline.
    """
    case = _load_case(case_id)
    return {
        "case_id": case["case_id"],
        "title": case["title"],
        "severity": case["severity"],
        "status": case["status"],
        "created_at": case["created_at"],
        "source_system": case["source_system"],
        "description": case["description"],
        "alert_count": len(case["alerts"]),
        "affected_asset_count": len(case["affected_assets"]),
        "snow_incident_ref": case["snow_incident_ref"],
        "iocs": case["iocs"],
        "timeline": case["timeline"],
    }


def list_alerts(case_id: str) -> list[dict]:
    """List all security alerts associated with a case.

    Args:
        case_id: The SecOps case identifier (e.g. CASE-001)

    Returns:
        List of alert dicts with severity, rule name, source/destination IPs, and timestamp.
    """
    case = _load_case(case_id)
    return case["alerts"]


def get_raw_logs(case_id: str) -> str:
    """Retrieve raw CEF-format log lines associated with a case.

    Args:
        case_id: The SecOps case identifier (e.g. CASE-001)

    Returns:
        Raw CEF syslog text from the case log fixture file.
    """
    log_file = CASES_DIR / f"{case_id.lower().replace('-', '_')}_logs.txt"
    if not log_file.exists():
        return f"No log fixture found for {case_id}"
    with open(log_file, encoding="utf-8") as f:
        return f.read()


def get_affected_assets(case_id: str) -> list[dict]:
    """Get all affected assets (endpoints, users, IPs) for a case.

    Args:
        case_id: The SecOps case identifier (e.g. CASE-001)

    Returns:
        List of asset dicts with hostname, IP, OS, user, and role.
    """
    case = _load_case(case_id)
    return case["affected_assets"]


def trigger_playbook(playbook_id: str, case_id: str) -> dict:
    """Trigger a SOAR playbook execution for a given case.

    Args:
        playbook_id: The playbook identifier to execute (e.g. PB-003)
        case_id: The SecOps case to run the playbook against (e.g. CASE-001)

    Returns:
        Execution result with execution_id and action steps list.
    """
    soar = _load_soar()
    actions = soar.get("playbook_actions", {}).get(playbook_id, [])
    execution_id = f"EXEC-{playbook_id}-{case_id}-{os.urandom(4).hex().upper()}"
    return {
        "execution_id": execution_id,
        "playbook_id": playbook_id,
        "case_id": case_id,
        "status": "initiated",
        "action_steps": actions,
        "message": f"Playbook {playbook_id} initiated successfully for case {case_id}",
    }


def update_case_status(case_id: str, status: str, notes: str) -> dict:
    """Update the resolution status and add closure notes to a SecOps case.

    Args:
        case_id: The SecOps case identifier (e.g. CASE-001)
        status: New case status (e.g. RESOLVED, CLOSED)
        notes: Resolution notes to attach to the case

    Returns:
        Acknowledgement dict with updated status.
    """
    return {
        "case_id": case_id,
        "updated_status": status,
        "notes_added": True,
        "message": f"Case {case_id} status updated to {status}",
    }
