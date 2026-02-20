#!/bin/bash
#
#Common variables

# TODO: Populate CURRENT_PROJECT_ID to whatever your project ID is
export CURRENT_PROJECT_ID="sibghat-test-project2"

# CURRENT project related variables
export CURRENT_PROJECT_REGION='us-west1'
export CURRENT_PROJECT_ZONE="${CURRENT_PROJECT_REGION}-a"

# CURRENT resource related variables
export CURRENT_ARTIFACT_REPOSITORY=${CURRENT_ARTIFACT_REPOSITORY:-${CURRENT_PROJECT_ID}-artifact-repo}
export CURRENT_PROJECT_REPOSITORY_REGION=${CURRENT_PROJECT_REPOSITORY_REGION:-'us'}

# CURRENT Workload related variables
export CURRENT_WORKLOAD_SERVICE_ACCOUNT=${CURRENT_WORKLOAD_SERVICE_ACCOUNT:-workload-sa}
export CURRENT_WORKLOAD_IMAGE_NAME=${CURRENT_WORKLOAD_IMAGE_NAME:-workload-container}
export CURRENT_WORKLOAD_IMAGE_TAG=${CURRENT_WORKLOAD_IMAGE_TAG:-latest}

# CURRENT MIG name and healthcheck
export TEMPLATE_NAME="${CURRENT_PROJECT_ID}-cs-sev-debug-template"
export CURRENT_MIG_NAME="${CURRENT_PROJECT_ID}-test-mig"
export ALLOW_HEALTH_CHECK_FIREWALL_RULE_NAME="allow-health-check-${CURRENT_PROJECT_ID}-test-mig"
export HEALTH_CHECK_NAME="${CURRENT_PROJECT_ID}-cs-sev-debug-health-check"