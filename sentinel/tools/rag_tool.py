"""
RAG Tool — semantic search for SOAR playbooks.

POC:  Local TF-IDF search over markdown files.
PROD: Discovery Engine API call to Agentspace (Vertex AI Search) datastore.

Switch by setting AGENTSPACE_DATASTORE_ID in the environment.
"""

import math
import os
import re
from pathlib import Path

# ── PROD: Agentspace / Vertex AI Search ─────────────────────────────────────────
DATASTORE_ID = os.getenv("AGENTSPACE_DATASTORE_ID", "")
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "")

def _query_agentspace(query_text: str, top_k: int) -> list[dict]:
    """Production: query the Vertex AI Search datastore."""
    from google.cloud import discoveryengine_v1 as discoveryengine

    client = discoveryengine.SearchServiceClient()
    serving_config = (
        f"projects/{PROJECT_ID}/locations/global"
        f"/collections/default_collection/dataStores/{DATASTORE_ID}"
        f"/servingConfigs/default_config"
    )

    request = discoveryengine.SearchRequest(
        serving_config=serving_config,
        query=query_text,
        page_size=top_k,
    )
    response = client.search(request)

    results = []
    for result in response.results:
        doc = result.document
        struct = doc.derived_struct_data

        # Fallback parsing if metadata mapping isn't perfect
        file_uri = doc.name
        title = struct.get("title", "")
        # Try to extract PB-XXX from title or uri
        pb_match = re.search(r'(PB-\d{3})', title) or re.search(r'(PB-\d{3})', file_uri)
        playbook_id = pb_match.group(1) if pb_match else "UNKNOWN"

        snippets = struct.get("snippets", [{}])
        excerpt = snippets[0].get("snippet", "") if snippets else ""

        results.append({
            "playbook_id": playbook_id,
            "playbook_name": title or f"Playbook {playbook_id}",
            "relevance_score": 0.95,  # Vertex doesn't expose raw scores clearly in all views
            "excerpt": excerpt[:300] + "...",
            "file": file_uri,
        })
    return results


# ── POC: Local TF-IDF ───────────────────────────────────────────────────────────
PB_DIR = Path(__file__).parent.parent / "data" / "playbooks"

_corpus_cache = {}
_vocab = set()
_idf = {}

def _init_tf_idf():
    """Builds a rudimentary TF-IDF index for the playbook markdown files."""
    global _corpus_cache, _vocab, _idf
    if _corpus_cache: return

    for file_path in PB_DIR.glob("*.md"):
        content = file_path.read_text(encoding="utf-8").lower()
        words = re.findall(r'\w+', content)
        tf = {}
        for w in words:
            tf[w] = tf.get(w, 0) + 1
        _corpus_cache[file_path] = {"content": content, "tf": tf, "len": len(words)}
        _vocab.update(words)

    N = len(_corpus_cache)
    for w in _vocab:
        df = sum(1 for d in _corpus_cache.values() if w in d["tf"])
        _idf[w] = math.log(N / (df + 1))


def _score_poc(query_words: list[str], doc_tf: dict, doc_len: int) -> float:
    score = 0
    for w in query_words:
        if w in doc_tf:
            tf = doc_tf[w] / max(1, doc_len)
            score += tf * _idf.get(w, 0.0)
    return min(1.0, score * 10)


def _query_poc(query_text: str, top_k: int) -> list[dict]:
    _init_tf_idf()
    query_words = re.findall(r'\w+', query_text.lower())
    scores = []

    for path, data in _corpus_cache.items():
        base_score = _score_poc(query_words, data["tf"], data["len"])
        scores.append((base_score, path, data["content"]))

    scores.sort(key=lambda x: x[0], reverse=True)
    results = []

    for score, path, content in scores[:top_k]:
        pb_match = re.search(r'# (PB-\d{3}): (.*)', content, re.IGNORECASE)
        pb_id = pb_match.group(1) if pb_match else path.stem
        pb_name = pb_match.group(2) if pb_match else path.name

        results.append({
            "playbook_id": pb_id,
            "playbook_name": pb_name.strip(),
            "relevance_score": round(score, 2),
            "excerpt": content[:280].replace("\n", " ").strip() + "...",
            "file": str(path.name),
        })
    return results


# ── Dispatcher ──────────────────────────────────────────────────────────────────
def query_playbook_corpus(query_text: str, top_k: int = 3) -> list[dict]:
    """
    Query the SOAR playbook library for the most relevant response procedure.

    Args:
        query_text: The threat context or keywords to search for.
        top_k: Number of playbook matches to return.
    """
    if DATASTORE_ID and PROJECT_ID:
        return _query_agentspace(query_text, top_k)
    return _query_poc(query_text, top_k)
