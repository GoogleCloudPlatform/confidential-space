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
#   UWEAR_WORKLOAD_VM
#   UWEAR_WORKLOAD_SERVICE_ACCOUNT
# Arguments:
#   None
#######################################
delete_UWEAR_resources() {
  if [ ! -z "${UWEAR_PROJECT_ID}" ]; then
    echo "UWEAR_PROJECT_ID is set to ${UWEAR_PROJECT_ID}"
  else
    err "UWEAR_PROJECT_ID is not set, please set the UWEAR_PROJECT_ID with GCP project-id of UWEAR."
  fi
  set_gcp_project "${UWEAR_PROJECT_ID}"
  delete_artifact_repository "${UWEAR_ARTIFACT_REPOSITORY}" "${UWEAR_PROJECT_REPOSITORY_REGION}"

  gcloud compute instances delete uwear --zone us-west1-b

  delete_service_account "${UWEAR_WORKLOAD_SERVICE_ACCOUNT}"@"${UWEAR_PROJECT_ID}".iam.gserviceaccount.com
}

#######################################
# Cleanup cloud resources of USLEEP.
# Globals:
#   USLEEP_PROJECT_ID
#   USLEEP_ARTIFACT_REPOSITORY
#   USLEEP_WORKLOAD_VM
#   USLEEP_WORKLOAD_SERVICE_ACCOUNT
# Arguments:
#   None
#######################################
delete_USLEEP_resources() {
  if [ ! -z "${USLEEP_PROJECT_ID}" ]; then
    echo "USLEEP_PROJECT_ID is set to ${USLEEP_PROJECT_ID}"
  else
    err "USLEEP_PROJECT_ID is not set, please set the USLEEP_PROJECT_ID with GCP project-id of USLEEP."
  fi

  set_gcp_project "${USLEEP_PROJECT_ID}"
  delete_artifact_repository "${USLEEP_ARTIFACT_REPOSITORY}" "${USLEEP_PROJECT_REPOSITORY_REGION}"

  gcloud compute instances delete usleep --zone us-west1-b

  delete_service_account "${USLEEP_WORKLOAD_SERVICE_ACCOUNT}"@"${USLEEP_PROJECT_ID}".iam.gserviceaccount.com
}

main() {
  delete_UWEAR_resources
  delete_USLEEP_resources
}

main "$@"