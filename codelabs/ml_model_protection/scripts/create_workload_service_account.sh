#!/bin/bash
#
# Creates workload service-account.

set -uo pipefail

source config_env.sh
source common.sh

set_gcp_project "${SECUNDUS_PROJECT_ID}"

echo "Creating workload service-account "${WORKLOAD_SERVICEACCOUNT}" ..."
create_service_account "${WORKLOAD_SERVICEACCOUNT}"

echo "Granting roles/iam.serviceAccountUser role to workload operator ..."
if ! gcloud iam service-accounts add-iam-policy-binding "${WORKLOAD_SERVICEACCOUNT}"@"${SECUNDUS_PROJECT_ID}".iam.gserviceaccount.com \
  --member="user:$(gcloud config get-value account)" \
  --role="roles/iam.serviceAccountUser"; then
  err "Failed to grant roles/iam.serviceAccountUser role workload operator."
fi

echo "Granting roles/confidentialcomputing.workloadUser to service-account "${WORKLOAD_SERVICEACCOUNT}" ..."
if ! gcloud projects add-iam-policy-binding "${SECUNDUS_PROJECT_ID}" \
  --member="serviceAccount:"${WORKLOAD_SERVICEACCOUNT}"@"${SECUNDUS_PROJECT_ID}".iam.gserviceaccount.com" \
  --role="roles/confidentialcomputing.workloadUser"; then
  err "Failed to grant roles/confidentialcomputing.workloadUser to service-account "${WORKLOAD_SERVICEACCOUNT}"."
fi

echo "Granting roles/logging.logWriter to service-account "${WORKLOAD_SERVICEACCOUNT}" ..."
if ! gcloud projects add-iam-policy-binding "${SECUNDUS_PROJECT_ID}" \
  --member="serviceAccount:"${WORKLOAD_SERVICEACCOUNT}"@"${SECUNDUS_PROJECT_ID}".iam.gserviceaccount.com" \
  --role="roles/logging.logWriter"; then
  err "Failed to grant roles/logging.logWriter to service-account "${WORKLOAD_SERVICEACCOUNT}"."
fi

echo "Granting objectViewer role for "${SECUNDUS_INPUT_STORAGE_BUCKET}" to service-account "${WORKLOAD_SERVICEACCOUNT}" ..."
if ! gsutil iam ch \
  serviceAccount:"${WORKLOAD_SERVICEACCOUNT}"@"${SECUNDUS_PROJECT_ID}".iam.gserviceaccount.com:objectViewer \
  gs://"${SECUNDUS_INPUT_STORAGE_BUCKET}"; then
  err "Failed to grant objectViewer role for "${SECUNDUS_INPUT_STORAGE_BUCKET}" to service-account "${WORKLOAD_SERVICEACCOUNT}"."
fi

echo "Granting objectUser role for "${SECUNDUS_RESULT_STORAGE_BUCKET}" to service-account "${WORKLOAD_SERVICEACCOUNT}" ..."
if ! gsutil iam ch \
  serviceAccount:"${WORKLOAD_SERVICEACCOUNT}"@"${SECUNDUS_PROJECT_ID}".iam.gserviceaccount.com:objectUser \
  gs://"${SECUNDUS_RESULT_STORAGE_BUCKET}"; then
  err "Failed to grant objectUser role for "${SECUNDUS_RESULT_STORAGE_BUCKET}" to service-account "${WORKLOAD_SERVICEACCOUNT}"."
fi