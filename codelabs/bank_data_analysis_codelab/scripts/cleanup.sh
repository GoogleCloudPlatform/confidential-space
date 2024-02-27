#!/bin/bash
#
# Performs the cleanup of cloud resources.

source config_env.sh
source common.sh

#######################################
# Cleanup cloud resources of Primus Bank.
# Globals:
#   PRIMUS_PROJECT_ID
#   PRIMUS_INPUT_STORAGE_BUCKET
#   PRIMUS_ENC_KEY
#   PRIMUS_SERVICE_ACCOUNT
#   PRIMUS_WORKLOAD_IDENTITY_POOL
#   PRIMUS_ARTIFACT_REPOSITORY
# Arguments:
#   None
#######################################
delete_primus_bank_resources() {
  if [ ! -z ${PRIMUS_PROJECT_ID} ]; then
    echo "PRIMUS_PROJECT_ID is set to ${PRIMUS_PROJECT_ID}"
  else
    err "PRIMUS_PROJECT_ID is not set, please set the PRIMUS_PROJECT_ID with GCP project-id of Primus Bank."
  fi
  set_gcp_project ${PRIMUS_PROJECT_ID}
  delete_storage_bucket ${PRIMUS_INPUT_STORAGE_BUCKET}
  delete_artifact_repository ${PRIMUS_ARTIFACT_REPOSITORY} ${PRIMUS_PROJECT_REPOSITORY_REGION}
  destroy_kms_key ${PRIMUS_ENC_KEY}  ${PRIMUS_ENC_KEYRING} ${PRIMUS_PROJECT_LOCATION}
  delete_workload_identity_pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ${PRIMUS_PROJECT_LOCATION}
  delete_service_account ${PRIMUS_SERVICE_ACCOUNT}@${PRIMUS_PROJECT_ID}.iam.gserviceaccount.com
}

#######################################
# Cleanup cloud resources of Secundus Bank.
# Globals:
#   SECUNDUS_PROJECT_ID
#   WORKLOAD_VM
#   WORKLOAD_SERVICE_ACCOUNT
#   SECUNDUS_PROJECT_ID
#   SECUNDUS_INPUT_STORAGE_BUCKET
#   SECUNDUS_ENC_KEY
#   SECUNDUS_SERVICE_ACCOUNT
#   SECUNDUS_WORKLOAD_IDENTITY_POOL
# Arguments:
#   None
#######################################
delete_secundus_bank_resources() {
  if [ ! -z ${SECUNDUS_PROJECT_ID} ]; then
    echo "SECUNDUS_PROJECT_ID is set to ${SECUNDUS_PROJECT_ID}"
  else
    err "SECUNDUS_PROJECT_ID is not set, please set the SECUNDUS_PROJECT_ID with GCP project-id of Secundus Bank."
  fi

  set_gcp_project ${SECUNDUS_PROJECT_ID}

  gcloud compute instances list  | grep ${WORKLOAD_VM}
  if [[ $? -eq 0 ]]; then
    echo "Deleting the workload VM ${WORKLOAD_VM}..."
    gcloud compute instances delete ${WORKLOAD_VM}
    if [[ $? -eq 0 ]]; then
      echo "Workload VM ${1} is deleted successfully."
    else
      err "Failed to delete workload VM ${1}."
    fi
  else
    echo "Workload VM ${1} doesn't exist. Skipping the deletion of workload VM ${1} ..."
  fi

  set_gcp_project ${SECUNDUS_PROJECT_ID}
  delete_storage_bucket ${SECUNDUS_INPUT_STORAGE_BUCKET}
  destroy_kms_key ${SECUNDUS_ENC_KEY}  ${SECUNDUS_ENC_KEYRING} ${SECUNDUS_PROJECT_LOCATION}
  delete_workload_identity_pool ${SECUNDUS_WORKLOAD_IDENTITY_POOL} ${SECUNDUS_PROJECT_LOCATION}
  delete_service_account ${SECUNDUS_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com
  delete_service_account ${WORKLOAD_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com
}

main() {
  delete_primus_bank_resources
  delete_secundus_bank_resources
}

main "$@"