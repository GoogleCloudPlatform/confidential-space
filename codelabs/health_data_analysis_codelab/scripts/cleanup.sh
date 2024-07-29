#!/bin/bash
#
# Performs the cleanup of cloud resources.

source config_env.sh
source common.sh

#######################################
# Cleanup cloud resources of UWEAR.
# Globals:
#   UWEAR_PROJECT_ID
#   UWEAR_ARTIFACT_REPOSITORY
# Arguments:
#   None
#######################################
delete_UWEAR_resources() {
  if [ ! -z ${UWEAR_PROJECT_ID} ]; then
    echo "UWEAR_PROJECT_ID is set to ${UWEAR_PROJECT_ID}"
  else
    err "UWEAR_PROJECT_ID is not set, please set the UWEAR_PROJECT_ID with GCP project-id of UWEAR."
  fi
  set_gcp_project ${UWEAR_PROJECT_ID}
  delete_artifact_repository ${UWEAR_ARTIFACT_REPOSITORY} ${UWEAR_PROJECT_REPOSITORY_REGION}
}

#######################################
# Cleanup cloud resources of USLEEP.
# Globals:
#   USLEEP_PROJECT_ID
#   WORKLOAD_VM
#   WORKLOAD_SERVICE_ACCOUNT
# Arguments:
#   None
#######################################
delete_USLEEP_resources() {
  if [ ! -z ${USLEEP_PROJECT_ID} ]; then
    echo "USLEEP_PROJECT_ID is set to ${USLEEP_PROJECT_ID}"
  else
    err "USLEEP_PROJECT_ID is not set, please set the USLEEP_PROJECT_ID with GCP project-id of USLEEP."
  fi

  set_gcp_project ${USLEEP_PROJECT_ID}

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

  set_gcp_project ${USLEEP_PROJECT_ID}
  delete_service_account ${WORKLOAD_SERVICE_ACCOUNT}@${USLEEP_PROJECT_ID}.iam.gserviceaccount.com
}

main() {
  delete_UWEAR_resources
  delete_USLEEP_resources
}

main "$@"