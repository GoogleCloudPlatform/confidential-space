#!/bin/bash
#
# Performs the cleanup of cloud resources.

set -uo pipefail

source config_env.sh
source common.sh

if [ ! -z "${PRIMUS_PROJECT_ID}" ]; then
  echo "PRIMUS_PROJECT_ID is set to "${PRIMUS_PROJECT_ID}""
else
  err "PRIMUS_PROJECT_ID is not set, please set the PRIMUS_PROJECT_ID with GCP project-id."
fi

set_gcp_project "${PRIMUS_PROJECT_ID}"

delete_storage_bucket "${PRIMUS_INPUT_STORAGE_BUCKET}"

delete_storage_bucket "${PRIMUS_RESULT_STORAGE_BUCKET}"

destroy_kms_key "${PRIMUS_KEY}" "${PRIMUS_KEYRING}" "${PRIMUS_PROJECT_LOCATION}"

delete_workload_identity_pool "${PRIMUS_WORKLOAD_IDENTITY_POOL}" "${PRIMUS_PROJECT_LOCATION}"

delete_service_account "${PRIMUS_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com

delete_artifact_repository "${PRIMUS_ARTIFACT_REPOSITORY}" "${PRIMUS_PROJECT_REPOSITORY_REGION}"

gcloud compute instances list --zones=${PRIMUS_PROJECT_ZONE} | grep ${WORKLOAD_VM}
if [[ $? -eq 0 ]]; then
  echo "Deleting the workload VM ${WORKLOAD_VM}..."
  gcloud compute instances delete ${WORKLOAD_VM}
  if [[ $? -eq 0 ]]; then
    echo "Workload VM ${WORKLOAD_VM} is deleted successfully."
  else
    err "Failed to delete workload VM ${WORKLOAD_VM}."
  fi
else
  echo "Workload VM ${WORKLOAD_VM} doesn't exist. Skipping the deletion of workload VM ${WORKLOAD_VM} ..."
fi