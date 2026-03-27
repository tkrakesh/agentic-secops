"""
Standard Agents definition for ADK Web Debugger.
Exposes specialized agents for easy discovery.
"""
from sentinel.agents.orchestrator import soc_orchestrator
from sentinel.agents.enrichment import enrichment_agent
from sentinel.agents.threat_analyst import threat_analyst_agent
from sentinel.agents.action_executor import action_executor_agent

# Use _agent suffix to ensure ADK Web Discovery
soc_orchestrator_agent = soc_orchestrator
enrichment_worker_agent = enrichment_agent
analyst_agent = threat_analyst_agent
executor_agent = action_executor_agent
