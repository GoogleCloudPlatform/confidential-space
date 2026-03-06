#!/bin/bash
#
# Performs the cleanup of cloud resources.

source config_env.sh
source common.sh

#######################################
# Cleanup cloud resources of UWEAR.
# Globals:
#   CURRENT_PROJECT_ID
#   CURRENT_ARTIFACT_REPOSITORY
#   CURRENT_PROJECT_REPOSITORY_REGION
#   CURRENT_WORKLOAD_SERVICE_ACCOUNT
#   CURRENT_MIG_NAME
#   HEALTH_CHECK_NAME
#   CURRENT_PROJECT_ZONE
#   TEMPALTE_NAME
# Arguments:
#   None
#######################################
delete_resources() {
  if [[ -n "${CURRENT_PROJECT_ID}" ]]; then
    echo "CURRENT_PROJECT_ID is set to ${CURRENT_PROJECT_ID}"
  else
    err "CURRENT_PROJECT_ID is not set, please set the CURRENT_PROJECT_ID with GCP project-id of current project."
  fi
  set_gcp_project "${CURRENT_PROJECT_ID}"
  delete_artifact_repository "${CURRENT_ARTIFACT_REPOSITORY}" "${CURRENT_PROJECT_REPOSITORY_REGION}"


  gcloud compute instance-groups managed delete "${CURRENT_MIG_NAME}" --zone "${CURRENT_PROJECT_ZONE}"
  gcloud compute health-checks delete "${HEALTH_CHECK_NAME}" --global
  gcloud compute instance-groups managed stop-autoscaling "${CURRENT_MIG_NAME}" --zone "${CURRENT_PROJECT_ZONE}"
  gcloud compute instance-templates delete "${TEMPLATE_NAME}" --zone "${CURRENT_PROJECT_ZONE}"

  delete_service_account "${CURRENT_WORKLOAD_SERVICE_ACCOUNT}"@"${CURRENT_PROJECT_ID}".iam.gserviceaccount.com
}

main() {
  delete_resources
}

main "$@"
