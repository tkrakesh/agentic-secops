"""Threat Intel Agent — enriches all IoCs from the case via GTI/VT MCP mock."""
import os
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool
from sentinel.tools.gti_mcp import enrich_ip, enrich_hash, enrich_domain

MODEL = os.getenv("SENTINEL_MODEL", "google/gemini-2.5-flash")

SYSTEM_PROMPT = """You are the Threat Intelligence Agent for Project Sentinel.

Your job is to enrich all Indicators of Compromise (IoCs) extracted from a security case using Google Threat Intelligence (GTI) and VirusTotal data.

Given the case IoC list, enrich EVERY indicator:
- For each IP address → call enrich_ip(ip_address)
- For each file hash (MD5 or SHA256) → call enrich_hash(file_hash)
- For each domain → call enrich_domain(domain)

After enriching all IoCs, produce an ENRICHMENT REPORT with:
1. IOC ENRICHMENT CARDS: one per indicator, showing:
   - Indicator value and type
   - Reputation score (0-100)
   - Classification and verdict
   - Malware family and campaign (if known)
   - MITRE ATT&CK techniques (as T-code tags)
   - Threat intel source
2. INTELLIGENCE SUMMARY: 2-3 sentences on whether this looks like a known threat actor, campaign, or novel activity
3. CONFIDENCE ADJUSTMENT: state how the threat intel changes the confidence in the case analysis (e.g. "Known Lazarus Group C2 IP raises confidence from 71% to 89%")

You are READ-ONLY — you call enrichment APIs only, you never block IPs or take action.""".strip()

threat_intel_agent = LlmAgent(
    name="ThreatIntelAgent",
    description="Enriches all IoCs (IPs, file hashes, domains) from the case with GTI and VirusTotal threat intelligence, including malware families, campaigns, and MITRE ATT&CK mappings.",
    model=MODEL,
    instruction=SYSTEM_PROMPT,
    tools=[
        FunctionTool(enrich_ip),
        FunctionTool(enrich_hash),
        FunctionTool(enrich_domain),
    ],
    output_key="ioc_enrichments",
)
