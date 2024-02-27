#!/bin/bash
#
# Creates workload service-account.

source config_env.sh
source common.sh

set_gcp_project ${SECUNDUS_PROJECT_ID}

echo "Creating workload service-account ${WORKLOAD_SERVICE_ACCOUNT} under project ${SECUNDUS_PROJECT_ID}..."
create_service_account ${WORKLOAD_SERVICE_ACCOUNT}

echo "Granting roles/iam.serviceAccountUser role to workload operator ..."
if ! gcloud iam service-accounts add-iam-policy-binding ${WORKLOAD_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com \
  --member="user:$(gcloud config get-value account)" \
  --role="roles/iam.serviceAccountUser"; then
  err "Failed to grant roles/iam.serviceAccountUser role workload operator $(gcloud config get-value account) under project ${SECUNDUS_PROJECT_ID}."
fi

echo "Granting roles/confidentialcomputing.workloadUser to service-account ${WORKLOAD_SERVICE_ACCOUNT} ..."
if ! gcloud projects add-iam-policy-binding ${SECUNDUS_PROJECT_ID} \
  --member="serviceAccount:${WORKLOAD_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/confidentialcomputing.workloadUser"; then
  err "Failed to grant roles/confidentialcomputing.workloadUser to service-account ${WORKLOAD_SERVICE_ACCOUNT}."
fi

echo "Granting roles/logging.logWriter to service-account ${WORKLOAD_SERVICE_ACCOUNT} ..."
if ! gcloud projects add-iam-policy-binding ${SECUNDUS_PROJECT_ID} \
  --member="serviceAccount:${WORKLOAD_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/logging.logWriter"; then
  err "Failed to grant roles/logging.logWriter to service-account ${WORKLOAD_SERVICE_ACCOUNT}."
fi

echo "Granting objectViewer role for ${PRIMUS_INPUT_STORAGE_BUCKET} to service-account ${WORKLOAD_SERVICE_ACCOUNT} ..."
if ! gsutil iam ch \
  serviceAccount:${WORKLOAD_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com:objectViewer \
  gs://${PRIMUS_INPUT_STORAGE_BUCKET}; then
  err "Failed to grant objectViewer role for ${PRIMUS_INPUT_STORAGE_BUCKET} to service-account ${WORKLOAD_SERVICE_ACCOUNT}."
fi

echo "Granting objectViewer role for ${SECUNDUS_INPUT_STORAGE_BUCKET} to service-account ${WORKLOAD_SERVICE_ACCOUNT} ..."
if ! gsutil iam ch \
  serviceAccount:${WORKLOAD_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com:objectViewer \
  gs://${SECUNDUS_INPUT_STORAGE_BUCKET}; then
  err "Failed to grant objectViewer role for ${SECUNDUS_INPUT_STORAGE_BUCKET} to service-account ${WORKLOAD_SERVICE_ACCOUNT}."
fi

echo "Granting objectCreator role for ${SECUNDUS_RESULT_STORAGE_BUCKET} to service-account ${WORKLOAD_SERVICE_ACCOUNT} ..."
if ! gsutil iam ch \
  serviceAccount:${WORKLOAD_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com:objectCreator \
  gs://${SECUNDUS_RESULT_STORAGE_BUCKET}; then
  err "Failed to grant objectCreator role for ${SECUNDUS_RESULT_STORAGE_BUCKET} to service-account ${WORKLOAD_SERVICE_ACCOUNT}."
fi