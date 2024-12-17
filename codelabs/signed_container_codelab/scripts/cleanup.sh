#!/bin/bash
#
# Performs the cleanup of the cloud resources.

source config_env.sh
source common.sh

#######################################
# Deletes the cloud resources of Primus bank.
# Globals:
#   PRIMUS_PROJECT_ID
#   PRIMUS_INPUT_STORAGE_BUCKET
#   PRIMUS_ENC_KEY
#   PRIMUS_ENC_KEYRING
#   PRIMUS_SIGNING_KEY
#   PRIMUS_SIGNING_KEYRING
#   PRIMUS_SERVICEACCOUNT
#   PRIMUS_WORKLOAD_IDENTITY_POOL
#   PRIMUS_COSIGN_REPOSITORY
# Arguments:
#   None
#######################################
delete_primus_bank_resources() {
  if [ ! -z ${PRIMUS_PROJECT_ID} ]; then
    echo "PRIMUS_PROJECT_ID is set to ${PRIMUS_PROJECT_ID}"
  else
    err "PRIMUS_PROJECT_ID is not set, please set the PRIMUS_PROJECT_ID with GCP project-id of primus bank."
  fi

  set_gcp_project ${PRIMUS_PROJECT_ID}

  confirmation=$(get_confirmation "Are you sure you want to delete the bucket ${PRIMUS_INPUT_STORAGE_BUCKET} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_storage_bucket ${PRIMUS_INPUT_STORAGE_BUCKET}
  else
    echo "Skipping the deletion of the bucket ${PRIMUS_INPUT_STORAGE_BUCKET} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the artifact registry ${PRIMUS_COSIGN_REPOSITORY} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_artifact_repository ${PRIMUS_COSIGN_REPOSITORY} ${PRIMUS_PROJECT_REPOSITORY_REGION}
  else
    echo "Skipping the deletion of the artifact registry ${PRIMUS_COSIGN_REPOSITORY} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the KMS key ${PRIMUS_ENC_KEY} ?")
  if [[ "${confirmation}" == "true" ]]; then
    destroy_kms_key ${PRIMUS_ENC_KEY}  ${PRIMUS_ENC_KEYRING} ${PRIMUS_PROJECT_LOCATION}
  else
    echo "Skipping the deletion of the KMS key ${PRIMUS_ENC_KEY} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the KMS key ${PRIMUS_SIGNING_KEY} ?")
  if [[ "${confirmation}" == "true" ]]; then
    destroy_kms_key ${PRIMUS_SIGNING_KEY}  ${PRIMUS_SIGNING_KEYRING} ${PRIMUS_PROJECT_LOCATION}
  else
    echo "Skipping the deletion of the KMS key ${PRIMUS_SIGNING_KEY} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the workload identity pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_workload_identity_pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ${PRIMUS_PROJECT_LOCATION}
  else
    echo "Skipping the deletion of the workload identity pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the serviceaccount ${PRIMUS_SERVICEACCOUNT}@${PRIMUS_PROJECT_ID}.iam.gserviceaccount.com ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_service_account ${PRIMUS_SERVICEACCOUNT}@${PRIMUS_PROJECT_ID}.iam.gserviceaccount.com
  else
    echo "Skipping the deletion of the serviceaccount ${PRIMUS_SERVICEACCOUNT}@${PRIMUS_PROJECT_ID}.iam.gserviceaccount.com ..."
  fi
}

#######################################
# Deletes the cloud resources of Secundus bank.
# Globals:
#   SECUNDUS_PROJECT_ID
#   SECUNDUS_ARTIFACT_REPOSITORY
#   WORKLOAD_VM
#   WORKLOAD_SERVICEACCOUNT
# Arguments:
#   None
#######################################
delete_secundus_bank_resources() {
  if [ ! -z ${SECUNDUS_PROJECT_ID} ]; then
    echo "SECUNDUS_PROJECT_ID is set to ${SECUNDUS_PROJECT_ID}"
  else
    err "SECUNDUS_PROJECT_ID is not set, please set the SECUNDUS_PROJECT_ID with GCP project-id of primus bank."
  fi

  set_gcp_project ${SECUNDUS_PROJECT_ID}

  confirmation=$(get_confirmation "Are you sure you want to delete the artifact registry ${SECUNDUS_ARTIFACT_REPOSITORY} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_artifact_repository ${SECUNDUS_ARTIFACT_REPOSITORY} ${SECUNDUS_PROJECT_REPOSITORY_REGION}
  else
    echo "Skipping the deletion of the artifact registry ${SECUNDUS_ARTIFACT_REPOSITORY} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the serviceaccount ${WORKLOAD_SERVICEACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_service_account ${WORKLOAD_SERVICEACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com
  else
    echo "Skipping the deletion of the serviceaccount ${WORKLOAD_SERVICEACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the VM ${WORKLOAD_VM} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_vm ${WORKLOAD_VM} ${SECUNDUS_PROJECT_ZONE} ${SECUNDUS_PROJECT_ID}
  else
    echo "Skipping the deletion of the VM ${WORKLOAD_VM} ..."
  fi
}

main() {
  delete_primus_bank_resources
  delete_secundus_bank_resources
}

main "$@"