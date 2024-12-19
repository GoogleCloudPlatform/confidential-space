#!/bin/bash
#
# Performs the cleanup of cloud resources.

set -uo pipefail

source config_env.sh
source common.sh

#######################################
# Deletes the cloud resources of Primus.
# Globals:
#   PRIMUS_PROJECT_ID
#   PRIMUS_INPUT_STORAGE_BUCKET
#   PRIMUS_RESULT_STORAGE_BUCKET
#   PRIMUS_KEY
#   PRIMUS_KEYRING
#   PRIMUS_SERVICEACCOUNT
#   PRIMUS_WORKLOAD_IDENTITY_POOL
#   WORKLOAD_SERVICEACCOUNT
#   WORKLOAD_VM
# Arguments:
#   None
#######################################
delete_primus_resources() {
  if [ ! -z ${PRIMUS_PROJECT_ID} ]; then
    echo "PRIMUS_PROJECT_ID is set to ${PRIMUS_PROJECT_ID}"
  else
    err "PRIMUS_PROJECT_ID is not set, please set the PRIMUS_PROJECT_ID with GCP project-id of Primus."
  fi

  set_gcp_project ${PRIMUS_PROJECT_ID}

  confirmation=$(get_confirmation "Are you sure you want to delete the bucket ${PRIMUS_INPUT_STORAGE_BUCKET} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_storage_bucket "${PRIMUS_INPUT_STORAGE_BUCKET}"
  else
    echo "Skipping the deletion of the bucket ${PRIMUS_INPUT_STORAGE_BUCKET} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the bucket ${PRIMUS_RESULT_STORAGE_BUCKET} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_storage_bucket "${PRIMUS_RESULT_STORAGE_BUCKET}"
  else
    echo "Skipping the deletion of the bucket ${PRIMUS_RESULT_STORAGE_BUCKET} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the KMS key ${PRIMUS_KEY} ?")
  if [[ "${confirmation}" == "true" ]]; then
    destroy_kms_key "${PRIMUS_KEY}" "${PRIMUS_KEYRING}" "${PRIMUS_PROJECT_LOCATION}"
  else
    echo "Skipping the deletion of the KMS key ${PRIMUS_KEY} ..."
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

  confirmation=$(get_confirmation "Are you sure you want to delete the artifact repository ${PRIMUS_ARTIFACT_REPOSITORY} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_artifact_repository ${PRIMUS_ARTIFACT_REPOSITORY} ${PRIMUS_PROJECT_REPOSITORY_REGION}
  else
    echo "Skipping the deletion of the artifact repository ${PRIMUS_ARTIFACT_REPOSITORY} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the VM ${ETHEREUM_NODE} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_vm ${ETHEREUM_NODE} ${PRIMUS_PROJECT_ZONE} ${PRIMUS_PROJECT_ID}
  else
    echo "Skipping the deletion of the VM ${ETHEREUM_NODE} ..."
  fi

  confirmation=$(get_confirmation "Are you sure you want to delete the VM ${WORKLOAD_VM} ?")
  if [[ "${confirmation}" == "true" ]]; then
    delete_vm ${WORKLOAD_VM} ${PRIMUS_PROJECT_ZONE} ${PRIMUS_PROJECT_ID}
  else
    echo "Skipping the deletion of the VM ${WORKLOAD_VM} ..."
  fi
}

main() {
  delete_primus_resources
}

main "$@"