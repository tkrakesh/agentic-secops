# 🛡️ Agentic SecOps: AI-Driven SOC

Agentic SecOps is a next-generation SOC (Security Operations Centre) AIOps platform built with **Google ADK** and **Gemini 2.5 Flash**. It orchestrates a multi-agent team to analyze, triage, and remediate security incidents end-to-end.

## 🚀 Features
- **ADK Multi-Agent Orchestration**: Coordinating specialized agents for Case Retrieval, RAG Playbooks, and Threat Intel.
- **Conditional HITL**: High-confidence, low-severity cases are auto-approved for remediation.
- **Premium Dashboard**: Animated Streamlit UI with real-time SOC metrics, confidence bars, and audit trails.
- **Resilient Pipeline**: Automatic 429 request backoff and bulk enrichment to optimize Vertex AI quota usage.

---

## 🛠️ Installation & Setup

### 1. Prerequisites
- **Python 3.10 or higher**
- **Google Cloud Project** with Vertex AI API enabled.
- **GCP Credentials**: Authenticated via `gcloud auth application-default login`.

### 2. Clone and Install
```bash
git clone https://github.com/tkrakesh/agentic-secops.git
cd agentic-secops

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Configuration
Create a `.env` file in the root directory (refer to `.env.example` if provided):

```env
# Vertex AI Config
GOOGLE_GENAI_USE_VERTEXAI=true
GOOGLE_CLOUD_PROJECT=xxx-your-project-id-xxx
GOOGLE_CLOUD_LOCATION=us-central1
GOOGLE_API_KEY=xxx-optional-gemini-key-xxx

# Agentic SecOps Config
SENTINEL_MODEL=gemini-2.5-flash
```

### 4. Run the Application
```bash
streamlit run app.py
```
Open `http://localhost:8501` in your browser.

---

## 🏗️ Architecture
- **Root Orchestrator**: `sentinel/agents/orchestrator.py`
- ** spécialistes**: `sentinel/agents/`
- **Tools (Mock/Real)**: `sentinel/tools/`
- **UI & Pipeline Logic**: `app.py` & `runner.py`

## 📄 License
MIT License. Created for Agentic SecOps POC.

