#!/bin/bash
#
# Common variables.

set -uo pipefail

RANDOM_STRING=$(tr -dc a-z </dev/urandom | head -c 4)

# Project specific variables
export PRIMUS_PROJECT_REGION=${PRIMUS_PROJECT_REGION:-'us-west1'}
export PRIMUS_PROJECT_ZONE=${PRIMUS_PROJECT_ZONE:-'us-west1-b'}
export PRIMUS_PROJECT_LOCATION=${PRIMUS_PROJECT_LOCATION:-'global'}

# Multi-party Computation resources related variables
export PRIMUS_INPUT_STORAGE_BUCKET=${PRIMUS_INPUT_STORAGE_BUCKET:-${PRIMUS_PROJECT_ID}-mpc-input-bucket}
export PRIMUS_RESULT_STORAGE_BUCKET=${PRIMUS_RESULT_STORAGE_BUCKET:-${PRIMUS_PROJECT_ID}-mpc-result-bucket}
export PRIMUS_KEYRING=${PRIMUS_KEYRINGS:-${PRIMUS_PROJECT_ID}-mpc-keyring}
export PRIMUS_KEY=${PRIMUS_KEY:-${PRIMUS_PROJECT_ID}-mpc-key-${RANDOM_STRING}}
export PRIMUS_SERVICEACCOUNT=${PRIMUS_SERVICEACCOUNT:-mpc-sa}
export PRIMUS_WORKLOAD_IDENTITY_POOL=${PRIMUS_WORKLOAD_IDENTITY_POOL:-mpc-wip}
export PRIMUS_WIP_PROVIDER=${PRIMUS_WIP_PROVIDER:-mpc-attestation-verifier}
export PRIMUS_ARTIFACT_REPOSITORY=${PRIMUS_ARTIFACT_REPOSITORY:-${PRIMUS_PROJECT_ID}-mpc-artifact-repo}
export PRIMUS_PROJECT_REPOSITORY_REGION=${PRIMUS_PROJECT_REPOSITORY_REGION:-'us'}

# Workload related variables
export WORKLOAD_SERVICEACCOUNT=${WORKLOAD_SERVICEACCOUNT:-mpc-workload-sa}
export WORKLOAD_IMAGE_NAME=${WORKLOAD_IMAGE_NAME:-mpc-workload-container}
export WORKLOAD_IMAGE_TAG=${WORKLOAD_IMAGE_TAG:-latest}
export WORKLOAD_VM=${WORKLOAD_VM:-mpc-container-vm}

# Addtional environment variables
export ETHEREUM_NODE=${ETHEREUM_NODE:-mpc-lab-ethereum-node}