"""
Root-level bridge for ADK Web Debugger discovery.
Exports the main SOCOrchestrator agent.
"""
from sentinel.agents.orchestrator import soc_orchestrator

# ADK will discover variables ending in _agent or instances of LlmAgent
# We export it here so 'adk web .' finds it immediately.
soc_orchestrator_agent = soc_orchestrator
