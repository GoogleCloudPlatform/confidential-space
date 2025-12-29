#!/bin/bash
#
# Creates the workload service account.

source config_env.sh
source common.sh

set_gcp_project ${SECUNDUS_PROJECT_ID}

echo "Creating workload service-account ${WORKLOAD_SERVICEACCOUNT} ..."
create_service_account ${WORKLOAD_SERVICEACCOUNT}

echo "Granting roles/iam.serviceAccountUser role workload operator ..."
if ! gcloud iam service-accounts add-iam-policy-binding ${WORKLOAD_SERVICEACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com \
  --member="user:$(gcloud config get-value account)" \
  --role="roles/iam.serviceAccountUser"; then
  err "Failed to grant roles/iam.serviceAccountUser role workload operator."
fi

echo "Granting roles/confidentialcomputing.workloadUser to service-account ${WORKLOAD_SERVICEACCOUNT} ..."
if ! gcloud projects add-iam-policy-binding ${SECUNDUS_PROJECT_ID} \
  --member="serviceAccount:${WORKLOAD_SERVICEACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/confidentialcomputing.workloadUser"; then
  err "Failed to grant roles/confidentialcomputing.workloadUser to service-account ${WORKLOAD_SERVICEACCOUNT}."
fi

echo "Granting roles/logging.logWriter to service-account ${WORKLOAD_SERVICEACCOUNT} ..."
if ! gcloud projects add-iam-policy-binding ${SECUNDUS_PROJECT_ID} \
  --member="serviceAccount:${WORKLOAD_SERVICEACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/logging.logWriter"; then
  err "Failed to grant roles/logging.logWriter to service-account ${WORKLOAD_SERVICEACCOUNT}."
fi

echo "Granting objectViewer role for ${PRIMUS_INPUT_STORAGE_BUCKET} to service-account ${WORKLOAD_SERVICEACCOUNT} ..."
if ! gcloud storage buckets add-iam-policy-binding gs://${PRIMUS_INPUT_STORAGE_BUCKET} \
  --member="serviceAccount:${WORKLOAD_SERVICEACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"; then
  err "Failed to grant objectViewer role for ${PRIMUS_INPUT_STORAGE_BUCKET} to service-account ${WORKLOAD_SERVICEACCOUNT}."
fi

echo "Granting objectCreator role for ${SECUNDUS_RESULT_STORAGE_BUCKET} to service-account ${WORKLOAD_SERVICEACCOUNT} ..."
if ! gcloud storage buckets add-iam-policy-binding gs://${SECUNDUS_RESULT_STORAGE_BUCKET} \
  --member="serviceAccount:${WORKLOAD_SERVICEACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/storage.objectAdmin"; then
  err "Failed to grant objectCreator role for ${SECUNDUS_RESULT_STORAGE_BUCKET} to service-account ${WORKLOAD_SERVICEACCOUNT}."
fi