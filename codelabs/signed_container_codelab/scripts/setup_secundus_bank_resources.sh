#!/bin/bash
#
# Sets up the cloud resources for Secundus Bank (Workload Author and Workload Operator).

source config_env.sh
source common.sh

if [ ! -z ${SECUNDUS_PROJECT_ID} ]; then
  echo "SECUNDUS_PROJECT_ID is set to ${SECUNDUS_PROJECT_ID}";
else
  echo "SECUNDUS_PROJECT_ID is not set, please set the SECUNDUS_PROJECT_ID with GCP project-id of secundus bank";
  exit 1;
fi

set_gcp_project ${SECUNDUS_PROJECT_ID}

echo "Creating storage bucket ${SECUNDUS_RESULT_STORAGE_BUCKET} for secundus bank ..."
create_storage_bucket ${SECUNDUS_RESULT_STORAGE_BUCKET}