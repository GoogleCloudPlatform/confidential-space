#!/bin/bash
#
# Sets up the cloud resources for Secundus (Data Collabrator, Workload Author and Workload Operator).

source config_env.sh
source common.sh

PARENT_DIR=$(dirname ${PWD})

if [ ! -z "${SECUNDUS_PROJECT_ID}" ]; then 
  echo "SECUNDUS_PROJECT_ID is set to "${SECUNDUS_PROJECT_ID}"";
else 
  echo "SECUNDUS_PROJECT_ID is not set, please set the SECUNDUS_PROJECT_ID with GCP project-id of Secundus"; 
  exit 1;
fi

set_gcp_project "${SECUNDUS_PROJECT_ID}"


echo "Creating input storage bucket "${SECUNDUS_INPUT_STORAGE_BUCKET}" for storing the sample images owned by Secundus."
create_storage_bucket "${SECUNDUS_INPUT_STORAGE_BUCKET}"

echo "Creating result storage bucket "${SECUNDUS_RESULT_STORAGE_BUCKET}" for storing the result of workload execution."
create_storage_bucket "${SECUNDUS_RESULT_STORAGE_BUCKET}"

echo "Uploading the sample images to storage bucket "${SECUNDUS_INPUT_STORAGE_BUCKET}" ..."
gcloud storage cp "${PARENT_DIR}"/artifacts/sample_images/* gs://"${SECUNDUS_INPUT_STORAGE_BUCKET}"/
