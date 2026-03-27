"""
core/agent.py — ADK-discoverable root agent entry point.

Run via:  adk web --no-reload  (from the Agentic-SecOps directory)
Or the Streamlit app calls the agents directly via runner.py
"""

import os
from dotenv import load_dotenv

# Load .env from project root
load_dotenv()

# ADK expects GOOGLE_GENAI_USE_VERTEXAI, GOOGLE_CLOUD_PROJECT etc already in env
from core.agents.orchestrator import soc_orchestrator

# ADK discovers 'root_agent' by convention
root_agent = soc_orchestrator
