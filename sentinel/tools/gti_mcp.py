"""
Mock GTI/VT MCP Server — Google ADK FunctionTools

Enriches IoCs (IPs, file hashes, domains) using fixture data that mirrors
the real Google Threat Intelligence and VirusTotal API response schemas.
In production, replaced by live GTI API + VirusTotal Enterprise API calls.
"""

from __future__ import annotations
import json
from pathlib import Path

IOC_DIR = Path(__file__).parent.parent / "data" / "ioc"
 
import os
import json
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL")
if MCP_SERVER_URL:
    import httpx

_ip_cache: dict = {}
_hash_cache: dict = {}
_domain_cache: dict = {}


def _load_ips() -> dict:
    global _ip_cache
    if not _ip_cache:
        with open(IOC_DIR / "known_ips.json", encoding="utf-8") as f:
            _ip_cache = json.load(f)
    return _ip_cache


def _load_hashes() -> dict:
    global _hash_cache
    if not _hash_cache:
        with open(IOC_DIR / "known_hashes.json", encoding="utf-8") as f:
            _hash_cache = json.load(f)
    return _hash_cache


def _load_domains() -> dict:
    global _domain_cache
    if not _domain_cache:
        with open(IOC_DIR / "known_domains.json", encoding="utf-8") as f:
            _domain_cache = json.load(f)
    return _domain_cache
 
 
def _call_remote_tool(name: str, args: dict) -> dict:
    """Helper to call the remote MCP server if MCP_SERVER_URL is set."""
    if not MCP_SERVER_URL:
        return {}
    try:
        url = f"{MCP_SERVER_URL.rstrip('/')}/mcp"
        payload = {"method": "tools/call", "params": {"name": name, "arguments": args}}
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            res_content = resp.json()
            if isinstance(res_content, list) and len(res_content) > 0:
                text = res_content[0].get("text", "{}")
                return json.loads(text)
            return res_content
    except Exception as e:
        print(f"DEBUG: Remote GTI MCP call failed: {e}")
        return {}


# ── Tool Functions ─────────────────────────────────────────────────────────────

def enrich_ip(ip_address: str) -> dict:
    """Enrich an IP address with Google Threat Intelligence data.

    Args:
        ip_address: IPv4 address to look up (e.g. 45.33.32.156)

    Returns:
        Enrichment data including reputation score, malware family, campaign,
        MITRE ATT&CK techniques, and verdict.
    """
    ips = _load_ips()
    if ip_address in ips:
        return ips[ip_address]
    return {
        "ip": ip_address,
        "reputation_score": 0,
        "classification": "Unknown — not in threat intelligence database",
        "malware_family": None,
        "campaign": None,
        "mitre_techniques": [],
        "tags": [],
        "verdict": "Unknown",
        "threat_intel_source": "GTI (no match)",
    }


def enrich_hash(file_hash: str) -> dict:
    """Enrich a file hash (MD5 or SHA256) with VirusTotal / GTI intelligence.

    Args:
        file_hash: MD5 or SHA256 hash of the file to look up

    Returns:
        Enrichment data including file name, malware family, reputation score,
        MITRE ATT&CK techniques, and VirusTotal verdict.
    """
    hashes = _load_hashes()
    if file_hash in hashes:
        return hashes[file_hash]
    return {
        "hash": file_hash,
        "hash_type": "Unknown",
        "file_name": "Unknown",
        "reputation_score": 0,
        "classification": "Unknown — not in threat intelligence database",
        "malware_family": None,
        "campaign": None,
        "mitre_techniques": [],
        "tags": [],
        "verdict": "Unknown",
        "threat_intel_source": "VirusTotal (no match)",
    }


def enrich_domain(domain: str) -> dict:
    """Enrich a domain name with Google Threat Intelligence data.

    Args:
        domain: Domain name to look up (e.g. c2tunnel-exfil.xyz)

    Returns:
        Enrichment data including registration date, resolved IPs, malware family,
        MITRE ATT&CK techniques, and verdict.
    """
    domains = _load_domains()
    if domain in domains:
        return domains[domain]
    return {
        "domain": domain,
        "reputation_score": 0,
        "classification": "Unknown — not in threat intelligence database",
        "malware_family": None,
        "campaign": None,
        "registered_date": None,
        "resolved_ips": [],
        "mitre_techniques": [],
        "tags": [],
        "verdict": "Unknown",
        "threat_intel_source": "GTI (no match)",
    }
def bulk_enrich_iocs(ips: list[str] = [], hashes: list[str] = [], domains: list[str] = []) -> dict:
    """Enrich a list of multiple indicators (IPs, hashes, domains) in a single call.

    Args:
        ips: List of IPv4 addresses
        hashes: List of file hashes (MD5/SHA256)
        domains: List of domain names

    Returns:
        A dictionary containing lists of enrichment results for each type.
    """
    if MCP_SERVER_URL:
        remote = _call_remote_tool("bulk_enrich_iocs", {"ips": ips, "hashes": hashes, "domains": domains})
        if remote and "error" not in remote:
            return remote
 
    results = {
        "ips": [enrich_ip(ip) for ip in ips],
        "hashes": [enrich_hash(h) for h in hashes],
        "domains": [enrich_domain(d) for d in domains],
    }
    return results
