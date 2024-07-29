#!/bin/bash
#
#Common variables

RANDOM_STRING=$(tr -dc a-z </dev/urandom | head -c 4)

# UWEAR project related variables
export UWEAR_PROJECT_REGION=${UWEAR_PROJECT_REGION:-'us-west1'}
export UWEAR_PROJECT_ZONE=${UWEAR_PROJECT_ZONE:-'us-west1-b'}
export UWEAR_PROJECT_LOCATION=${UWEAR_PROJECT_LOCATION:-'global'}

# UWEAR resource related variables
export UWEAR_ARTIFACT_REPOSITORY=${UWEAR_ARTIFACT_REPOSITORY:-${UWEAR_PROJECT_ID}-artifact-repo}
export UWEAR_PROJECT_REPOSITORY_REGION=${UWEAR_PROJECT_REPOSITORY_REGION:-'us'}


# USLEEP project related variables
export USLEEP_PROJECT_REGION=${USLEEP_PROJECT_REGION:-'us-west1'}
export USLEEP_PROJECT_ZONE=${USLEEP_PROJECT_ZONE:-'us-west1-b'}
export USLEEP_PROJECT_LOCATION=${USLEEP_PROJECT_LOCATION:-'global'}

# Workload related variables
export WORKLOAD_SERVICE_ACCOUNT=${WORKLOAD_SERVICE_ACCOUNT:-workload-sa}
export WORKLOAD_IMAGE_NAME=${WORKLOAD_IMAGE_NAME:-workload-container}
export WORKLOAD_IMAGE_TAG=${WORKLOAD_IMAGE_TAG:-latest}