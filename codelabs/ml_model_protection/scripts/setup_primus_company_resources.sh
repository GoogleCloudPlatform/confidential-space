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
fi

set_gcp_project "${PRIMUS_PROJECT_ID}"

echo "Creating input storage bucket "${PRIMUS_INPUT_STORAGE_BUCKET}" for storing machine learning model of Primus ..."
create_storage_bucket "${PRIMUS_INPUT_STORAGE_BUCKET}"

echo "Creating service-account "${PRIMUS_SERVICEACCOUNT}" that has access to the machine learning model of Primus ..."
create_service_account "${PRIMUS_SERVICEACCOUNT}"

echo "Creating workload identity pool "${PRIMUS_WORKLOAD_IDENTITY_POOL}" ..."
create_workload_identity_pool "${PRIMUS_WORKLOAD_IDENTITY_POOL}" "${PRIMUS_PROJECT_LOCATION}"

gsutil iam ch \
  serviceAccount:"${PRIMUS_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com:legacyBucketReader \
  gs://"${PRIMUS_INPUT_STORAGE_BUCKET}"

gsutil iam ch \
  serviceAccount:"${PRIMUS_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com:objectViewer \
  gs://"${PRIMUS_INPUT_STORAGE_BUCKET}"

echo "Attaching the service-account "${PRIMUS_SERVICEACCOUNT}" to workload identity pool "${PRIMUS_WORKLOAD_IDENTITY_POOL}" ..."
gcloud iam service-accounts add-iam-policy-binding "${PRIMUS_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com \
  --member="principalSet://iam.googleapis.com/projects/"$(gcloud projects describe "${PRIMUS_PROJECT_ID}" \
    --format="value(projectNumber)")"/locations/"${PRIMUS_PROJECT_LOCATION}"/workloadIdentityPools/"${PRIMUS_WORKLOAD_IDENTITY_POOL}"/*" \
  --role=roles/iam.workloadIdentityUser