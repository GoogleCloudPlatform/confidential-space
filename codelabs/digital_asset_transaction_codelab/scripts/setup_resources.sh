#!/bin/bash
#
# Sets up the cloud resources for multi party computation.

set -uo pipefail

source config_env.sh
source common.sh

PARENT_DIR=$(dirname "${PWD}")

if [ ! -z "${PRIMUS_PROJECT_ID}" ]; then
  echo "PRIMUS_PROJECT_ID is set to ${PRIMUS_PROJECT_ID}"
else
  fatal "PRIMUS_PROJECT_ID is not set, please set the PRIMUS_PROJECT_ID with GCP project-id. Project-id can be set using 'export PRIMUS_PROJECT_ID=<your GCP Project-id>'."
fi

set_gcp_project "${PRIMUS_PROJECT_ID}"

echo "Creating input storage bucket ${PRIMUS_INPUT_STORAGE_BUCKET} ..."
create_storage_bucket "${PRIMUS_INPUT_STORAGE_BUCKET}"

echo "Creating result storage bucket ${PRIMUS_RESULT_STORAGE_BUCKET} ..."
create_storage_bucket "${PRIMUS_RESULT_STORAGE_BUCKET}"

echo "Creating keyring ${PRIMUS_KEYRING} for encryption key in KMS ..."
create_kms_keyring "${PRIMUS_KEYRING}" "${PRIMUS_PROJECT_LOCATION}"

echo "Creating encryption key ${PRIMUS_KEY} in KMS ..."
create_kms_encryption_key "${PRIMUS_KEY}" "${PRIMUS_KEYRING}" "${PRIMUS_PROJECT_LOCATION}"

echo "Encyping the sample data file of alice ..."
gcloud kms encrypt \
    --ciphertext-file=""${PARENT_DIR}"/artifacts/alice_encrypted_key_share" \
    --plaintext-file=""${PARENT_DIR}"/artifacts/alice_key_share" \
    --key=projects/"${PRIMUS_PROJECT_ID}"/locations/"${PRIMUS_PROJECT_LOCATION}"/keyRings/"${PRIMUS_KEYRING}"/cryptoKeys/"${PRIMUS_KEY}"

echo "Encyping the sample data file of bob ..."
gcloud kms encrypt \
    --ciphertext-file=""${PARENT_DIR}"/artifacts/bob_encrypted_key_share" \
    --plaintext-file=""${PARENT_DIR}"/artifacts/bob_key_share" \
    --key=projects/"${PRIMUS_PROJECT_ID}"/locations/"${PRIMUS_PROJECT_LOCATION}"/keyRings/"${PRIMUS_KEYRING}"/cryptoKeys/"${PRIMUS_KEY}"

echo "Uploading the encrypted file to storage bucket ${PRIMUS_INPUT_STORAGE_BUCKET}"
gcloud storage cp "${PARENT_DIR}"/artifacts/alice_encrypted_key_share gs://"${PRIMUS_INPUT_STORAGE_BUCKET}"/alice_encrypted_key_share
gcloud storage cp "${PARENT_DIR}"/artifacts/bob_encrypted_key_share gs://"${PRIMUS_INPUT_STORAGE_BUCKET}"/bob_encrypted_key_share

echo "Creating service-account ${PRIMUS_SERVICEACCOUNT} ..."
create_service_account "${PRIMUS_SERVICEACCOUNT}"

gcloud storage buckets add-iam-policy-binding gs://"${PRIMUS_INPUT_STORAGE_BUCKET}" \
  --member=serviceAccount:"${PRIMUS_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com \
  --role=roles/storage.objectViewer

echo "Granting KMS decryptor role to the service-account ${PRIMUS_SERVICEACCOUNT} ..."
gcloud kms keys add-iam-policy-binding \
  projects/"${PRIMUS_PROJECT_ID}"/locations/"${PRIMUS_PROJECT_LOCATION}"/keyRings/"${PRIMUS_KEYRING}"/cryptoKeys/"${PRIMUS_KEY}" \
    --member=serviceAccount:"${PRIMUS_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com \
    --role=roles/cloudkms.cryptoKeyDecrypter

echo "Creating workload identity pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ..."
create_workload_identity_pool "${PRIMUS_WORKLOAD_IDENTITY_POOL}" "${PRIMUS_PROJECT_LOCATION}"

echo "Attaching the service-account ${PRIMUS_SERVICEACCOUNT} to workload identity pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ..."
gcloud iam service-accounts add-iam-policy-binding "${PRIMUS_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com \
  --member="principalSet://iam.googleapis.com/projects/"$(gcloud projects describe "${PRIMUS_PROJECT_ID}" \
    --format="value(projectNumber)")"/locations/"${PRIMUS_PROJECT_LOCATION}"/workloadIdentityPools/"${PRIMUS_WORKLOAD_IDENTITY_POOL}"/*" \
  --role=roles/iam.workloadIdentityUser