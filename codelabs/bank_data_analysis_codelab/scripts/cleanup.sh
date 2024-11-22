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

  confirmation=$(get_confirmation "Are you sure you want to delete the bucket ${PRIMUS_INPUT_STORAGE_BUCKET} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_storage_bucket ${PRIMUS_INPUT_STORAGE_BUCKET}
  else
    echo "Skipping the deletion of the bucket ${PRIMUS_INPUT_STORAGE_BUCKET} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the artifact registry ${PRIMUS_ARTIFACT_REPOSITORY} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_artifact_repository ${PRIMUS_ARTIFACT_REPOSITORY} ${PRIMUS_PROJECT_REPOSITORY_REGION}
  else
    echo "Skipping the deletion of the artifact registry ${PRIMUS_ARTIFACT_REPOSITORY} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the KMS key ${PRIMUS_ENC_KEY} ?")
  if [[ "${confirmation}" == "true" ]]; then
    destroy_kms_key ${PRIMUS_ENC_KEY}  ${PRIMUS_ENC_KEYRING} ${PRIMUS_PROJECT_LOCATION}
  else
    echo "Skipping the deletion of the KMS key ${PRIMUS_ENC_KEY} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the workload identity pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_workload_identity_pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ${PRIMUS_PROJECT_LOCATION}
  else
    echo "Skipping the deletion of the workload identity pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the serviceaccount ${PRIMUS_SERVICE_ACCOUNT}@${PRIMUS_PROJECT_ID}.iam.gserviceaccount.com ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_service_account ${PRIMUS_SERVICE_ACCOUNT}@${PRIMUS_PROJECT_ID}.iam.gserviceaccount.com
  else
    echo "Skipping the deletion of the serviceaccount ${PRIMUS_SERVICE_ACCOUNT}@${PRIMUS_PROJECT_ID}.iam.gserviceaccount.com ..."
  fi
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

  confirmation=$(get_confirmation "Are you sure you want to delete the VM ${WORKLOAD_VM1} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_vm ${WORKLOAD_VM1} ${SECUNDUS_PROJECT_ZONE} ${SECUNDUS_PROJECT_ID}
  else
    echo "Skipping the deletion of the VM ${WORKLOAD_VM1} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the VM ${WORKLOAD_VM2} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_vm ${WORKLOAD_VM2} ${SECUNDUS_PROJECT_ZONE} ${SECUNDUS_PROJECT_ID}
  else
    echo "Skipping the deletion of the VM ${WORKLOAD_VM2} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the bucket ${SECUNDUS_INPUT_STORAGE_BUCKET} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_storage_bucket ${SECUNDUS_INPUT_STORAGE_BUCKET}
  else
    echo "Skipping the deletion of the bucket ${SECUNDUS_INPUT_STORAGE_BUCKET} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the KMS key ${SECUNDUS_ENC_KEY} ?")
  if [[ "${confirmation}" == "true" ]]; then
    destroy_kms_key ${SECUNDUS_ENC_KEY}  ${SECUNDUS_ENC_KEYRING} ${SECUNDUS_PROJECT_LOCATION}
  else
    echo "Skipping the deletion of the KMS key ${SECUNDUS_ENC_KEY} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the workload identity pool ${SECUNDUS_WORKLOAD_IDENTITY_POOL} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_workload_identity_pool ${SECUNDUS_WORKLOAD_IDENTITY_POOL} ${SECUNDUS_PROJECT_LOCATION}
  else
    echo "Skipping the deletion of the workload identity pool ${SECUNDUS_WORKLOAD_IDENTITY_POOL} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the serviceaccount ${SECUNDUS_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_service_account ${SECUNDUS_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com
  else
    echo "Skipping the deletion of the serviceaccount ${SECUNDUS_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the serviceaccount ${WORKLOAD_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_service_account ${WORKLOAD_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com
  else
    echo "Skipping the deletion of the serviceaccount ${WORKLOAD_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com ..."
  fi
}

main() {
  delete_primus_bank_resources
  delete_secundus_bank_resources
}

main "$@"