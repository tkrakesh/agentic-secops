import asyncio
import json
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from sentinel.tools.parallel_enrichment import run_parallel_enrichment

async def test_enrichment():
    print("Testing Parallel Enrichment for CASE-006...")
    res = await run_parallel_enrichment("CASE-006")
    print("Result keys:", res.keys())
    print("Success!")

if __name__ == "__main__":
    asyncio.run(test_enrichment())
