# 🚀 Agentic SecOps Deployment Guide

This guide covers how to deploy Agentic SecOps (Streamlit + Google ADK) to **Google Cloud Platform** using **Cloud Run**, ensuring native access to Vertex AI models.


## 🏗️ Deployment Architecture
- **Front-end / Orchestration**: Streamlit App (Containerized on Cloud Run)
- **Model Layer**: Vertex AI (Gemini 2.5 Flash)
- **Networking**: Public HTTPS endpoint (IAP-secured recommended)

---

## 🛠️ Step-by-Step Deployment

### 1. Project Setup
Ensure your Google Cloud Project is set up and billing is enabled.
```bash
# Set your project ID
export PROJECT_ID="xxx-your-project-id-xxx"
gcloud config set project $PROJECT_ID

# Enable required APIs
gcloud services enable \
    compute.googleapis.com \
    run.googleapis.com \
    artifactregistry.googleapis.com \
    aiplatform.googleapis.com \
    iam.googleapis.com
```

### 2. Prepare Container Image
Create a repository in **Artifact Registry** and push your Docker image:
```bash
# Create repository
gcloud artifacts repositories create sentinel-repo \
    --repository-format=docker \
    --location=us-central1

# Build and push using Cloud Build (fastest)
gcloud builds submit --tag us-central1-docker.pkg.dev/$PROJECT_ID/sentinel-repo/sentinel-app:latest .
```

### 3. Identity & Access Management (IAM)
The Cloud Run service needs permission to call Vertex AI.
```bash
# Create a dedicated Service Account
gcloud iam service-accounts create sentinel-runner-sa \
    --display-name="Agentic SecOps Cloud Run Service Account"

# Grant Vertex AI User role
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:sentinel-runner-sa@$PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/aiplatform.user"
```

### 4. Deploy to Cloud Run
Deploy the containerized app with the required environment variables:
```bash
gcloud run deploy project-sentinel \
    --image us-central1-docker.pkg.dev/$PROJECT_ID/sentinel-repo/sentinel-app:latest \
    --region us-central1 \
    --service-account sentinel-runner-sa@$PROJECT_ID.iam.gserviceaccount.com \
    --set-env-vars="GOOGLE_CLOUD_PROJECT=$PROJECT_ID,GOOGLE_GENAI_USE_VERTEX_AI=true,SENTINEL_MODEL=gemini-2.5-flash" \
    --allow-unauthenticated # Open to public (Use IAP for production)
```

---

## 🛡️ Production Hardening
- **Security**: Use [Identity-Aware Proxy (IAP)](https://cloud.google.com/iap) to restrict access to the dashboard.
- **Quota**: Monitor your **Vertex AI API** quotas (Requests Per Minute) in the Google Cloud Console.
- **Environment**: Use [Secret Manager](https://cloud.google.com/secret-manager) for sensitive variables like `GOOGLE_API_KEY`.

## 📈 Monitoring
- Check **Cloud Logging** for pipeline logs and agent reasoning turns.
- Use **Vertex AI Monitoring** to track model latency and token usage.
