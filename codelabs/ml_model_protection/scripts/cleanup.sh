#!/bin/bash
#
# Performs the cleanup of cloud resources.

set -uo pipefail

source config_env.sh
source common.sh

#######################################
# Cleanup cloud resources of Primus company.
# Globals:
#   PRIMUS_PROJECT_ID
#   PRIMUS_INPUT_STORAGE_BUCKET
#   PRIMUS_SERVICEACCOUNT
#   PRIMUS_WORKLOAD_IDENTITY_POOL
#   PRIMUS_ARTIFACT_REPOSITORY
# Arguments:
#   None
#######################################
delete_primus_bank_resources() {
  if [ ! -z "${PRIMUS_PROJECT_ID}" ]; then 
    echo "PRIMUS_PROJECT_ID is set to "${PRIMUS_PROJECT_ID}""
  else 
    err "PRIMUS_PROJECT_ID is not set, please set the PRIMUS_PROJECT_ID with GCP project-id of Primus company."
  fi

  set_gcp_project "${PRIMUS_PROJECT_ID}"
  delete_storage_bucket "${PRIMUS_INPUT_STORAGE_BUCKET}"
  delete_workload_identity_pool "${PRIMUS_WORKLOAD_IDENTITY_POOL}" "${PRIMUS_PROJECT_LOCATION}"
  delete_service_account "${PRIMUS_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com
  delete_artifact_repository "${PRIMUS_ARTIFACT_REPOSITORY}" "${PRIMUS_PROJECT_REPOSITORY_REGION}"
}

#######################################
# Cleanup cloud resources of Secundus company.
# Globals:
#   SECUNDUS_PROJECT_ID
#   SECUNDUS_INPUT_STORAGE_BUCKET
#   SECUNDUS_RESULT_STORAGE_BUCKET
#   WORKLOAD_VM
#   WORKLOAD_SERVICEACCOUNT
# Arguments:
#   None
#######################################
delete_secundus_bank_resources() {
  if [ ! -z "${SECUNDUS_PROJECT_ID}" ]; then 
    echo "SECUNDUS_PROJECT_ID is set to "${SECUNDUS_PROJECT_ID}""
  else 
    err "SECUNDUS_PROJECT_ID is not set, please set the SECUNDUS_PROJECT_ID with GCP project-id of Secundus company."
  fi

  set_gcp_project "${SECUNDUS_PROJECT_ID}"
  delete_storage_bucket "${SECUNDUS_INPUT_STORAGE_BUCKET}"
  delete_storage_bucket "${SECUNDUS_RESULT_STORAGE_BUCKET}"

  gcloud compute instances list  | grep "${WORKLOAD_VM}"
  if [[ $? -eq 0 ]]; then
    echo "Deleting the workload VM "${WORKLOAD_VM}"..."
    gcloud compute instances delete "${WORKLOAD_VM}"
    if [[ $? -eq 0 ]]; then
      echo "Workload VM "${1}" is deleted successfully."
    else
      err "Failed to delete workload VM "${1}"."
    fi
  else
    echo "Workload VM "${1}" doesn't exist. Skipping the deletion of workload VM "${1}" ..."
  fi

  delete_service_account "${WORKLOAD_SERVICEACCOUNT}"@"${SECUNDUS_PROJECT_ID}".iam.gserviceaccount.com
}

main() {
  delete_primus_bank_resources
  delete_secundus_bank_resources
}

main "$@"