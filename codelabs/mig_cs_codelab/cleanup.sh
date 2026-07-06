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
    exit 1
  fi
  set_gcp_project "${CURRENT_PROJECT_ID}"
  delete_artifact_repository "${CURRENT_ARTIFACT_REPOSITORY:?Error: CURRENT_ARTIFACT_REPOSITORY is not set or empty. Please set it in config_env.sh and run 'source config_env.sh' first.}" "${CURRENT_PROJECT_REPOSITORY_REGION:?Error: CURRENT_PROJECT_REPOSITORY_REGION is not set or empty. Please set it in config_env.sh and run 'source config_env.sh' first.}"


  gcloud compute instance-groups managed delete "${CURRENT_MIG_NAME:?Error: CURRENT_MIG_NAME is not set or empty. Please set it in config_env.sh and run 'source config_env.sh' first.}" --zone "${CURRENT_PROJECT_ZONE:?Error: CURRENT_PROJECT_ZONE is not set or empty. Please set it in config_env.sh and run 'source config_env.sh' first.}"
  gcloud compute health-checks delete "${HEALTH_CHECK_NAME:?Error: HEALTH_CHECK_NAME is not set or empty. Please set it in config_env.sh and run 'source config_env.sh' first.}" --global
  gcloud compute instance-groups managed stop-autoscaling "${CURRENT_MIG_NAME}" --zone "${CURRENT_PROJECT_ZONE}"
  gcloud compute instance-templates delete "${TEMPLATE_NAME:?Error: TEMPLATE_NAME is not set or empty. Please set it in config_env.sh and run 'source config_env.sh' first.}" --zone "${CURRENT_PROJECT_ZONE}"

  delete_service_account "${CURRENT_WORKLOAD_SERVICE_ACCOUNT:?Error: CURRENT_WORKLOAD_SERVICE_ACCOUNT is not set or empty. Please set it in config_env.sh and run 'source config_env.sh' first.}"@"${CURRENT_PROJECT_ID}".iam.gserviceaccount.com
}

main() {
  delete_resources
}

main "$@"
