"""Threat Intel Agent — enriches all IoCs from the case via GTI/VT MCP mock."""
import os
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool
from sentinel.tools.gti_mcp import bulk_enrich_iocs

MODEL = os.getenv("SENTINEL_MODEL", "google/gemini-2.5-flash")

SYSTEM_PROMPT = """You are the Threat Intelligence Agent for Project Sentinel.

Your job is to enrich all Indicators of Compromise (IoCs) extracted from a security case using Google Threat Intelligence (GTI) and VirusTotal data.

Given the case IoC list, perform a single bulk enrichment call:
- call bulk_enrich_iocs(ips=[...], hashes=[...], domains=[...]) with all collected indicators.

After enrichment, produce an ENRICHMENT REPORT with:
1. IOC ENRICHMENT CARDS: one per indicator, showing:
   - Indicator value and type
   - Reputation score (0-100)
   - Classification and verdict
   - Malware family and campaign (if known)
   - MITRE ATT&CK techniques (as T-code tags)
2. INTELLIGENCE SUMMARY: 2-3 sentences on the threat actor/campaign.
3. CONFIDENCE ADJUSTMENT: how this intel changes the original case analysis confidence.

You are READ-ONLY — you call enrichment APIs only."""

threat_intel_agent = LlmAgent(
    name="ThreatIntelAgent",
    description="Enriches all IoCs (IPs, file hashes, domains) in bulk with GTI and VirusTotal intelligence.",
    model=MODEL,
    instruction=SYSTEM_PROMPT,
    tools=[
        FunctionTool(bulk_enrich_iocs),
    ],
    output_key="ioc_enrichments",
)
