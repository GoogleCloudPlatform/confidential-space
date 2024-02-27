#!/bin/bash
#
# Sets up the cloud resources for Primus Bank (Data Collabrator).

source config_env.sh
source common.sh

PARENT_DIR=$(dirname ${PWD})

if [ ! -z ${PRIMUS_PROJECT_ID} ]; then
  echo "PRIMUS_PROJECT_ID is set to ${PRIMUS_PROJECT_ID}"
else
  err "PRIMUS_PROJECT_ID is not set, please set the PRIMUS_PROJECT_ID with GCP project-id of primus bank."
fi

set_gcp_project ${PRIMUS_PROJECT_ID}

echo "Creating input storage bucket ${PRIMUS_INPUT_STORAGE_BUCKET} for primus bank ..."
create_storage_bucket ${PRIMUS_INPUT_STORAGE_BUCKET}

echo "Creating keyring ${PRIMUS_ENC_KEYRING} for encryption key in KMS for primus bank ..."
create_kms_keyring ${PRIMUS_ENC_KEYRING} "global"

echo "Creating encryption key ${PRIMUS_ENC_KEY} in KMS for primus bank."
create_kms_encryption_key ${PRIMUS_ENC_KEY} ${PRIMUS_ENC_KEYRING} "global"

echo "Creating keyring ${PRIMUS_SIGNING_KEYRING} for signing key in KMS for primus bank ..."
create_kms_keyring ${PRIMUS_SIGNING_KEYRING} "global"

echo "Encrypting the sample data file of primus bank"
gcloud kms encrypt \
    --ciphertext-file="${PARENT_DIR}/artifacts/primus_enc_customer_list.csv" \
    --plaintext-file="${PARENT_DIR}/artifacts/primus_customer_list.csv" \
    --key=projects/${PRIMUS_PROJECT_ID}/locations/global/keyRings/${PRIMUS_ENC_KEYRING}/cryptoKeys/${PRIMUS_ENC_KEY}

echo "Uploading the encrypted file to storage bucket ${PRIMUS_INPUT_STORAGE_BUCKET}"
gsutil cp ${PARENT_DIR}/artifacts/primus_enc_customer_list.csv gs://${PRIMUS_INPUT_STORAGE_BUCKET}/primus_enc_customer_list.csv

echo "Creating service-account ${PRIMUS_SERVICEACCOUNT} for primus bank ..."
create_service_account ${PRIMUS_SERVICEACCOUNT}

echo "Granting KMS decryptor role to the service-account ${PRIMUS_SERVICEACCOUNT} ..."
gcloud kms keys add-iam-policy-binding \
  projects/${PRIMUS_PROJECT_ID}/locations/global/keyRings/${PRIMUS_ENC_KEYRING}/cryptoKeys/${PRIMUS_ENC_KEY} \
    --member=serviceAccount:${PRIMUS_SERVICEACCOUNT}@${PRIMUS_PROJECT_ID}.iam.gserviceaccount.com \
    --role=roles/cloudkms.cryptoKeyDecrypter

echo "Creating workload identity pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ..."
create_workload_identity_pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} "global"

echo "Attaching the service-account ${PRIMUS_SERVICEACCOUNT} to workload identity pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ..."
gcloud iam service-accounts add-iam-policy-binding ${PRIMUS_SERVICEACCOUNT}@${PRIMUS_PROJECT_ID}.iam.gserviceaccount.com \
  --member="principalSet://iam.googleapis.com/projects/"$(gcloud projects describe ${PRIMUS_PROJECT_ID} \
    --format="value(projectNumber)")"/locations/global/workloadIdentityPools/${PRIMUS_WORKLOAD_IDENTITY_POOL}/*" \
  --role=roles/iam.workloadIdentityUser