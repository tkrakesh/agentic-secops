#!/bin/bash
# Bootstrap Agentspace/Vertex AI Search Datastore for SOAR Playbooks
set -e

# Configuration
PROJECT_ID=$1
DATASTORE_ID="sentinel-playbooks-store"
BUCKET_NAME="gs://sentinel-playbooks-${PROJECT_ID}"
LOCATION="global"

if [ -z "$PROJECT_ID" ]; then
    echo "Usage: $0 <project_id>"
    exit 1
fi

echo ">> Creating GCS bucket: $BUCKET_NAME"
gcloud storage buckets create "${BUCKET_NAME}" --project="${PROJECT_ID}" --location="us-central1" || true

echo ">> Uploading playbook markdown files to GCS"
# Ensure we are in project root
gcloud storage cp sentinel/data/playbooks/*.md "${BUCKET_NAME}/playbooks/"

echo ">> Target Datastore ID: ${DATASTORE_ID}"
echo ""
echo "============================================================"
echo "ACTION REQUIRED: Create the Datastore in Google Cloud Console"
echo "============================================================"
echo "1. Go to: https://console.cloud.google.com/gen-app-builder/data-stores?project=${PROJECT_ID}"
echo "2. Click 'Create Data Store'"
echo "3. Select 'Cloud Storage' source"
echo "4. Enter bucket path: ${BUCKET_NAME}/playbooks/*"
echo "5. Select 'Unstructured documents'"
echo "6. Name it: ${DATASTORE_ID}"
echo "7. Click Create"
echo ""
echo "Once created, update your .env with the full datastore path:"
echo "AGENTSPACE_DATASTORE_ID=${DATASTORE_ID}"
echo "============================================================"
