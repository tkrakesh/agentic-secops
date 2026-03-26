"""
Mock ServiceNow MCP Server — Google ADK FunctionTools

Simulates ServiceNow ITSM REST API calls using in-memory state + fixture data.
In production, replaced by real ServiceNow REST API v2 calls via MCP.
"""

from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path

SNOW_FILE = Path(__file__).parent.parent / "data" / "snow" / "inc_template.json"

# In-memory SNOW state — simulates a live SNOW instance for the demo
_snow_state: dict = {}


def _get_incident_db() -> dict:
    global _snow_state
    if not _snow_state:
        with open(SNOW_FILE, encoding="utf-8") as f:
            data = json.load(f)
        _snow_state = dict(data.get("mock_incidents", {}))
    return _snow_state


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Tool Functions ─────────────────────────────────────────────────────────────

def get_incident(inc_number: str) -> dict:
    """Retrieve a ServiceNow incident record by INC number.

    Args:
        inc_number: ServiceNow incident number (e.g. INC0041892)

    Returns:
        Incident record dict with all fields.
    """
    db = _get_incident_db()
    if inc_number in db:
        return db[inc_number]
    return {"error": f"Incident {inc_number} not found", "inc_number": inc_number}


def create_incident(short_description: str, description: str, priority: str, case_id: str) -> dict:
    """Create a new ServiceNow incident record linked to a SecOps case.

    Args:
        short_description: One-line incident description
        description: Full incident description
        priority: Priority level (1-Critical, 2-High, 3-Medium, 4-Low)
        case_id: Linked SecOps case ID

    Returns:
        Created incident with INC number and sys_id.
    """
    db = _get_incident_db()
    inc_num = f"INC{str(len(db) + 1042000).zfill(7)}"
    incident = {
        "number": inc_num,
        "priority": priority,
        "state": "Open",
        "category": "Security",
        "short_description": short_description,
        "description": description,
        "opened_at": _now(),
        "linked_case": case_id,
        "work_notes": [],
        "approval_records": [],
    }
    db[inc_num] = incident
    return {"created": True, "number": inc_num, "sys_id": f"SNOW-SYS-{case_id}"}


def update_incident(inc_number: str, fields: dict) -> dict:
    """Update fields on an existing ServiceNow incident.

    Args:
        inc_number: ServiceNow incident number to update
        fields: Dict of field name → new value pairs

    Returns:
        Update acknowledgement with changed fields.
    """
    db = _get_incident_db()
    if inc_number not in db:
        return {"error": f"Incident {inc_number} not found"}
    db[inc_number].update(fields)
    return {"updated": True, "number": inc_number, "updated_fields": list(fields.keys())}


def add_worknote(inc_number: str, note: str, author: str = "Agentic SecOps AI") -> dict:
    """Add a timestamped work note to a ServiceNow incident.

    Args:
        inc_number: ServiceNow incident number
        note: Work note text to append
        author: Author identifier for the note

    Returns:
        Acknowledgement with note ID.
    """
    db = _get_incident_db()
    if inc_number not in db:
        return {"error": f"Incident {inc_number} not found"}
    if "work_notes" not in db[inc_number]:
        db[inc_number]["work_notes"] = []
    worknote = {
        "id": f"WN-{len(db[inc_number]['work_notes']) + 1:04d}",
        "timestamp": _now(),
        "author": author,
        "note": note,
    }
    db[inc_number]["work_notes"].append(worknote)
    return {"added": True, "note_id": worknote["id"], "inc_number": inc_number}


def close_incident(inc_number: str, close_notes: str, close_code: str = "Resolved by Change") -> dict:
    """Close a ServiceNow incident with resolution notes.

    Args:
        inc_number: ServiceNow incident number to close
        close_notes: Detailed resolution notes explaining what was done and why
        close_code: SNOW close code (default: Resolved by Change)

    Returns:
        Closure acknowledgement with resolved timestamps.
    """
    db = _get_incident_db()
    if inc_number not in db:
        return {"error": f"Incident {inc_number} not found"}
    resolved_at = _now()
    db[inc_number].update({
        "state": "Resolved",
        "close_code": close_code,
        "close_notes": close_notes,
        "resolved_at": resolved_at,
        "resolved_by": "Agentic SecOps Orchestrator (AI)",
    })
    return {
        "closed": True,
        "number": inc_number,
        "state": "Resolved",
        "resolved_at": resolved_at,
        "close_notes_preview": close_notes[:100] + "..." if len(close_notes) > 100 else close_notes,
    }


def get_incident_state(inc_number: str) -> dict:
    """Get current in-memory state of a SNOW incident (for HITL audit trail rendering).

    Args:
        inc_number: ServiceNow incident number

    Returns:
        Full current incident record including work notes and approval records.
    """
    db = _get_incident_db()
    return db.get(inc_number, {"error": f"Incident {inc_number} not found"})
