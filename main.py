"""
Main entry point for Google Cloud ADK Web Debugger.
Run: google-adk web --app main:app
"""
import os
from google.adk.apps import App
from sentinel.agents.orchestrator import soc_orchestrator

# Initialize the ADK App with our root agent
app = App(
    name="Agentic SecOps SOC Platform",
    root_agent=soc_orchestrator,
)

if __name__ == "__main__":
    import sys
    print("To launch the ADK Web Debugger, run:")
    print("google-adk web --app main:app")
