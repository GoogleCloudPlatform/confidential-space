#!/bin/bash
#
# Sets required varibles for the codelab.

# Primus company's GCP project related variables
export PRIMUS_PROJECT_REGION=${PRIMUS_PROJECT_REGION:-'us-west1'}
export PRIMUS_PROJECT_ZONE=${PRIMUS_PROJECT_ZONE:-'us-west1-b'}
export PRIMUS_PROJECT_LOCATION=${PRIMUS_PROJECT_LOCATION:-'global'}

# Primus company's GCP resource related variables
export PRIMUS_ENC_KEY=${PRIMUS_ENC_KEY:-${PRIMUS_PROJECT_ID}-enc-key}
export PRIMUS_ENC_KEYRING=${PRIMUS_ENC_KEYRING:-${PRIMUS_PROJECT_ID}-enc-kr}
export PRIMUS_ENC_KEYVERSION=${PRIMUS_ENC_KEYVERSION:-1}
export PRIMUS_SERVICEACCOUNT=${PRIMUS_SERVICEACCOUNT:-primus-sa}
export PRIMUS_WIP_PROVIDER=${PRIMUS_WIP_PROVIDER:-primus-wip-provider}
export PRIMUS_WORKLOAD_IDENTITY_POOL=${PRIMUS_WORKLOAD_IDENTITY_POOL:-primus-wip}
export PRIMUS_ARTIFACT_REPOSITORY=${PRIMUS_ARTIFACT_REPOSITORY:-${PRIMUS_PROJECT_ID}-artifact-repo}
export PRIMUS_PROJECT_REPOSITORY_REGION=${PRIMUS_PROJECT_REPOSITORY_REGION:-'us'}

# Workload related variables
export WORKLOAD_SERVICEACCOUNT=${WORKLOAD_SERVICEACCOUNT:-workload-sa}
export WORKLOAD_IMAGE_NAME=${WORKLOAD_IMAGE_NAME:-workload-container}
export WORKLOAD_IMAGE_TAG=${WORKLOAD_IMAGE_TAG:-latest}
export WORKLOAD_VM=${WORKLOAD_VM:-workload-vm}

# Workload client related variables
export CLIENT_VM=${CLIENT_VM:-client-vm}
export CLIENT_SERVICEACCOUNT=${CLIENT_SERVICEACCOUNT:-client-sa}