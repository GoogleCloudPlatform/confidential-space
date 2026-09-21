#!/bin/bash
#
# Sets up the cloud resources for Primus (Data Collaborator).

source config_env.sh
source common.sh

PARENT_DIR=$(dirname ${PWD})

if [ ! -z "${PRIMUS_PROJECT_ID}" ]; then 
  echo "PRIMUS_PROJECT_ID is set to "${PRIMUS_PROJECT_ID}""
else 
  err "PRIMUS_PROJECT_ID is not set, please set the PRIMUS_PROJECT_ID with GCP project-id of Primus."
  exit 1
fi

set_gcp_project "${PRIMUS_PROJECT_ID}"

echo "Creating input storage bucket "${PRIMUS_INPUT_STORAGE_BUCKET}" for storing the protected data of Primus ..."
create_storage_bucket "${PRIMUS_INPUT_STORAGE_BUCKET}"

echo "Creating workload identity pool "${PRIMUS_WORKLOAD_IDENTITY_POOL}" ..."
create_workload_identity_pool "${PRIMUS_WORKLOAD_IDENTITY_POOL}" "${PRIMUS_PROJECT_LOCATION}"

PRIMUS_PROJECT_NUMBER=$(gcloud projects describe "${PRIMUS_PROJECT_ID}" --format="value(projectNumber)")
PRINCIPAL_SET="principalSet://iam.googleapis.com/projects/${PRIMUS_PROJECT_NUMBER}/locations/${PRIMUS_PROJECT_LOCATION}/workloadIdentityPools/${PRIMUS_WORKLOAD_IDENTITY_POOL}/*"

echo "Granting direct read access on bucket ${PRIMUS_INPUT_STORAGE_BUCKET} to workload identity pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ..."
gsutil iam ch "${PRINCIPAL_SET}":legacyBucketReader gs://"${PRIMUS_INPUT_STORAGE_BUCKET}"
gsutil iam ch "${PRINCIPAL_SET}":objectViewer gs://"${PRIMUS_INPUT_STORAGE_BUCKET}"

echo "Generating a sample protected data file and uploading it to bucket ${PRIMUS_INPUT_STORAGE_BUCKET} ..."
echo "Confidential data owned by Primus, accessible only after ITA attestation." > /tmp/data.txt
gsutil cp /tmp/data.txt gs://"${PRIMUS_INPUT_STORAGE_BUCKET}"/data.txt
rm /tmp/data.txt

echo "Primus resources setup completed successfully."
