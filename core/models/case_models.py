"""
Agentic SecOps — Pydantic output schemas

These match the design document specification exactly and are used to
enforce structured output from Gemini via the ADK output_schema parameter.
"""

from __future__ import annotations
from typing import Literal
from pydantic import BaseModel, Field


class MitreTechnique(BaseModel):
    technique_id: str = Field(description="MITRE ATT&CK technique ID, e.g. T1078")
    technique_name: str = Field(description="Human-readable technique name, e.g. Valid Accounts")
    tactic: str = Field(description="MITRE tactic category, e.g. Credential Access")


class IoCEnrichment(BaseModel):
    indicator: str = Field(description="The raw indicator value (IP, hash, or domain)")
    indicator_type: Literal["ip", "hash", "domain"]
    reputation_score: int = Field(ge=0, le=100, description="0=clean, 100=most malicious")
    malware_family: str | None = Field(default=None, description="Associated malware family if known")
    campaign: str | None = Field(default=None, description="Threat campaign name if known")
    verdict: str = Field(description="Malicious / Suspicious / Clean / Unknown")
    mitre_techniques: list[str] = Field(default_factory=list, description="List of MITRE technique IDs")


class CaseAnalysis(BaseModel):
    case_id: str
    case_summary: str = Field(
        description="3-5 sentence analyst-readable prose summary of the case, threat, and recommended action"
    )
    threat_classification: str = Field(
        description="Short threat classification label, e.g. 'Credential Abuse / Lateral Movement'"
    )
    severity: Literal["Critical", "High", "Medium", "Low"]
    mitre_techniques: list[MitreTechnique]
    blast_radius_endpoints: int = Field(description="Number of endpoints affected")
    blast_radius_users: int = Field(description="Number of user accounts affected")
    recommended_playbook_id: str = Field(description="Playbook ID, e.g. PB-003")
    recommended_playbook_name: str = Field(description="Human-readable playbook name")
    playbook_rationale: str = Field(
        description="1-2 sentence explanation of why this playbook was selected over alternatives"
    )
    confidence_score: float = Field(ge=0.0, le=1.0, description="Confidence in the recommendation (0.0–1.0)")
    ioc_enrichments: list[IoCEnrichment]
    actions_to_approve: list[str] = Field(
        description="Ordered list of actions the analyst must take or approve"
    )
    estimated_containment_time_minutes: int = Field(description="Estimated time to full containment in minutes")


class PlaybookMatch(BaseModel):
    playbook_id: str
    playbook_name: str
    relevance_score: float = Field(ge=0.0, le=1.0)
    excerpt: str = Field(description="Most relevant passage from the playbook")
    trigger_conditions_met: list[str] = Field(description="Which trigger conditions were matched")
