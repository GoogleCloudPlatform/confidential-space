#!/bin/bash
#
# Creates a Cloud Run Job and Cloud Scheduler trigger to automate MIG updates.

# Source your common variables if not already set in the environment
# source common.sh

# --- DERIVED VARIABLES ---
# We use the variables defined in your common script to build the resource names

# The container image for the updater script
# Uses: CURRENT_PROJECT_REPOSITORY_REGION, CURRENT_PROJECT_ID, CURRENT_ARTIFACT_REPOSITORY
CONTAINER_IMAGE="${CURRENT_PROJECT_REPOSITORY_REGION}-docker.pkg.dev/${CURRENT_PROJECT_ID}/${CURRENT_ARTIFACT_REPOSITORY}/update-script:latest"

# Job and Scheduler Names (Derived from the MIG Name)
JOB_NAME="${CURRENT_MIG_NAME}-updater"
SCHEDULER_NAME="${CURRENT_MIG_NAME}-scheduler"

# Service Account Email construction
# Uses: CURRENT_WORKLOAD_SERVICE_ACCOUNT, CURRENT_PROJECT_ID
SERVICE_ACCOUNT_EMAIL="${CURRENT_WORKLOAD_SERVICE_ACCOUNT}@${CURRENT_PROJECT_ID}.iam.gserviceaccount.com"

# Schedule: Every 15 minutes
SCHEDULE="*/15 * * * *"


# ---------------------------------------------------------
# 1. Create (or Update) the Cloud Run Job
# ---------------------------------------------------------
echo "Deploying Cloud Run Job: ${JOB_NAME}..."

# We attempt to update; if it fails (doesn't exist), we create it.
# Uses: CURRENT_PROJECT_REGION

if gcloud run jobs describe "${JOB_NAME}" --region "${CURRENT_PROJECT_REGION}" > /dev/null 2>&1; then
    echo "Job exists. Updating image..."
    gcloud run jobs update "${JOB_NAME}" \
        --image "${CONTAINER_IMAGE}" \
        --region "${CURRENT_PROJECT_REGION}" \
        --quiet
else
    echo "Creating new job..."
    gcloud run jobs create "${JOB_NAME}" \
        --image "${CONTAINER_IMAGE}" \
        --region "${CURRENT_PROJECT_REGION}" \
        --quiet
fi


# ---------------------------------------------------------
# 2. Create the Cloud Scheduler Trigger
# ---------------------------------------------------------
echo "Creating Cloud Scheduler..."

# The URI to trigger a Cloud Run Job is specific:
# Uses: CURRENT_PROJECT_REGION, CURRENT_PROJECT_ID
JOB_URI="https://${CURRENT_PROJECT_REGION}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${CURRENT_PROJECT_ID}/jobs/${JOB_NAME}:run"

if gcloud scheduler jobs describe "${SCHEDULER_NAME}" --location "${CURRENT_PROJECT_REGION}" > /dev/null 2>&1; then
    echo "Scheduler exists. Updating..."
    gcloud scheduler jobs update http "${SCHEDULER_NAME}" \
        --location "${CURRENT_PROJECT_REGION}" \
        --schedule "${SCHEDULE}" \
        --uri "${JOB_URI}" \
        --http-method POST \
        --oauth-service-account-email "${SERVICE_ACCOUNT_EMAIL}"
else
    echo "Creating new schedule..."
    gcloud scheduler jobs create http "${SCHEDULER_NAME}" \
        --location "${CURRENT_PROJECT_REGION}" \
        --schedule "${SCHEDULE}" \
        --uri "${JOB_URI}" \
        --http-method POST \
        --oauth-service-account-email "${SERVICE_ACCOUNT_EMAIL}"
fi

echo "------------------------------------------------"
echo "Setup Complete."
echo "Job Name:      ${JOB_NAME}"
echo "Schedule Name: ${SCHEDULER_NAME}"
echo "Frequency:     ${SCHEDULE}"
echo "To run manually now: gcloud run jobs execute ${JOB_NAME} --region ${CURRENT_PROJECT_REGION}"