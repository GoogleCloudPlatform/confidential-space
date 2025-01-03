#!/bin/bash
#
# Creates workload service-account.

set -uo pipefail

source config_env.sh
source common.sh

set_gcp_project "${PRIMUS_PROJECT_ID}"

echo "Creating workload service-account ${WORKLOAD_SERVICEACCOUNT}"
create_service_account "${WORKLOAD_SERVICEACCOUNT}"

echo "Granting roles/iam.serviceAccountUser role workload operator ..."
gcloud iam service-accounts add-iam-policy-binding "${WORKLOAD_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com \
  --member="user:$(gcloud config get-value account)" \
  --role="roles/iam.serviceAccountUser"

echo "Granting roles/confidentialcomputing.workloadUser to service-account ${WORKLOAD_SERVICEACCOUNT} ..."
gcloud projects add-iam-policy-binding "${PRIMUS_PROJECT_ID}" \
  --member="serviceAccount:"${WORKLOAD_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com" \
  --role="roles/confidentialcomputing.workloadUser"

echo "Granting roles/logging.logWriter to service-account ${WORKLOAD_SERVICEACCOUNT} ..."
gcloud projects add-iam-policy-binding "${PRIMUS_PROJECT_ID}" \
  --member="serviceAccount:"${WORKLOAD_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com" \
  --role="roles/logging.logWriter"

echo "Granting objectViewer role for ${PRIMUS_INPUT_STORAGE_BUCKET} to service-account ${WORKLOAD_SERVICEACCOUNT} ..."
gsutil iam ch \
  serviceAccount:"${WORKLOAD_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com:objectViewer \
  gs://"${PRIMUS_INPUT_STORAGE_BUCKET}"

echo "Granting objectAdmin role for ${PRIMUS_RESULT_STORAGE_BUCKET} to service-account ${WORKLOAD_SERVICEACCOUNT} ..."
gsutil iam ch \
  serviceAccount:"${WORKLOAD_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com:objectAdmin \
  gs://"${PRIMUS_RESULT_STORAGE_BUCKET}"