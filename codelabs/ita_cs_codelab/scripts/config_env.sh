#!/bin/bash
#
# Common variables for Intel Trust Authority (ITA) Confidential Space codelab.

RANDOM_STRING=$(tr -dc a-z </dev/urandom | head -c 4)

# Primus Company project related variables (Data Owner & Workload Author)
export PRIMUS_PROJECT_REGION=${PRIMUS_PROJECT_REGION:-'us-central1'}
export PRIMUS_PROJECT_ZONE=${PRIMUS_PROJECT_ZONE:-'us-central1-c'}
export PRIMUS_PROJECT_LOCATION=${PRIMUS_PROJECT_LOCATION:-'global'}

# Primus Company resource related variables
export PRIMUS_INPUT_STORAGE_BUCKET=${PRIMUS_INPUT_STORAGE_BUCKET:-${PRIMUS_PROJECT_ID}-input-bucket}
export PRIMUS_WIP_PROVIDER=${PRIMUS_WIP_PROVIDER:-primus-wip-provider}
export PRIMUS_WORKLOAD_IDENTITY_POOL=${PRIMUS_WORKLOAD_IDENTITY_POOL:-primus-wip}
export PRIMUS_ARTIFACT_REPOSITORY=${PRIMUS_ARTIFACT_REPOSITORY:-${PRIMUS_PROJECT_ID}-artifact-repo}
export PRIMUS_PROJECT_REPOSITORY_REGION=${PRIMUS_PROJECT_REPOSITORY_REGION:-'us'}

# Secundus Company project related variables (Operator)
export SECUNDUS_PROJECT_REGION=${SECUNDUS_PROJECT_REGION:-'us-central1'}
export SECUNDUS_PROJECT_ZONE=${SECUNDUS_PROJECT_ZONE:-'us-central1-c'}
export SECUNDUS_PROJECT_LOCATION=${SECUNDUS_PROJECT_LOCATION:-'global'}
export SECUNDUS_PROJECT_REPOSITORY_REGION=${SECUNDUS_PROJECT_REPOSITORY_REGION:-'us'}

# Secundus Company resource related variables
export SECUNDUS_INPUT_STORAGE_BUCKET=${SECUNDUS_INPUT_STORAGE_BUCKET:-${SECUNDUS_PROJECT_ID}-input-bucket}
export SECUNDUS_SERVICEACCOUNT=${SECUNDUS_SERVICEACCOUNT:-${SECUNDUS_PROJECT_ID}-sa}
export SECUNDUS_RESULT_STORAGE_BUCKET=${SECUNDUS_RESULT_STORAGE_BUCKET:-${SECUNDUS_PROJECT_ID}-result-bucket}

# Workload related variables
export WORKLOAD_SERVICEACCOUNT=${WORKLOAD_SERVICEACCOUNT:-workload-sa}
export WORKLOAD_IMAGE_NAME=${WORKLOAD_IMAGE_NAME:-workload-container}
export WORKLOAD_IMAGE_TAG=${WORKLOAD_IMAGE_TAG:-latest}
export WORKLOAD_VM=${WORKLOAD_VM:-workload-vm}

# Intel Trust Authority related variables
export ITA_REGION=${ITA_REGION:-'US'}
