#!/bin/bash
#
# Sets up the cloud resources for Primus Bank (Data Collaborator).

source config_env.sh
source common.sh

PARENT_DIR=$(dirname ${PWD})

if [ ! -z ${PRIMUS_PROJECT_ID} ]; then
  echo "PRIMUS_PROJECT_ID is set to ${PRIMUS_PROJECT_ID}"
else
  err "PRIMUS_PROJECT_ID is not set, please set the PRIMUS_PROJECT_ID with GCP project-id of primus bank."
fi

set_gcp_project ${PRIMUS_PROJECT_ID}

echo "Creating input storage bucket ${PRIMUS_INPUT_STORAGE_BUCKET} to store the customer data of Primus Bank ..."
create_storage_bucket ${PRIMUS_INPUT_STORAGE_BUCKET}

echo "Creating keyring ${PRIMUS_ENC_KEYRING} for encryption key in KMS for Primus Bank ..."
create_kms_keyring ${PRIMUS_ENC_KEYRING} ${PRIMUS_PROJECT_LOCATION}

echo "Creating encryption key ${PRIMUS_ENC_KEY} in KMS that will use to encrypt the customer data of Primus Bank ..."
create_kms_encryption_key ${PRIMUS_ENC_KEY} ${PRIMUS_ENC_KEYRING} ${PRIMUS_PROJECT_LOCATION}

echo "Encrypting the customer data file of Primus Bank ..."
gcloud kms encrypt \
    --ciphertext-file="${PARENT_DIR}/artifacts/primus_enc_customer_list.csv" \
    --plaintext-file="${PARENT_DIR}/artifacts/primus_customer_list.csv" \
    --key=projects/${PRIMUS_PROJECT_ID}/locations/${PRIMUS_PROJECT_LOCATION}/keyRings/${PRIMUS_ENC_KEYRING}/cryptoKeys/${PRIMUS_ENC_KEY}

echo "Uploading the encrypted file to storage bucket ${PRIMUS_INPUT_STORAGE_BUCKET} ..."
gsutil cp ${PARENT_DIR}/artifacts/primus_enc_customer_list.csv gs://${PRIMUS_INPUT_STORAGE_BUCKET}/primus_enc_customer_list.csv

echo "Creating service-account ${PRIMUS_SERVICE_ACCOUNT} for Primus Bank."
create_service_account ${PRIMUS_SERVICE_ACCOUNT}

echo "Granting KMS decryptor role to the service-account ${PRIMUS_SERVICE_ACCOUNT} ..."
gcloud kms keys add-iam-policy-binding \
  projects/${PRIMUS_PROJECT_ID}/locations/${PRIMUS_PROJECT_LOCATION}/keyRings/${PRIMUS_ENC_KEYRING}/cryptoKeys/${PRIMUS_ENC_KEY} \
    --member=serviceAccount:${PRIMUS_SERVICE_ACCOUNT}@${PRIMUS_PROJECT_ID}.iam.gserviceaccount.com \
    --role=roles/cloudkms.cryptoKeyDecrypter

echo "Creating workload identity pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ..."
create_workload_identity_pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ${PRIMUS_PROJECT_LOCATION}

echo "Attaching the service-account ${PRIMUS_SERVICE_ACCOUNT} to workload identity pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ..."
gcloud iam service-accounts add-iam-policy-binding ${PRIMUS_SERVICE_ACCOUNT}@${PRIMUS_PROJECT_ID}.iam.gserviceaccount.com \
  --member="principalSet://iam.googleapis.com/projects/"$(gcloud projects describe ${PRIMUS_PROJECT_ID} \
    --format="value(projectNumber)")"/locations/${PRIMUS_PROJECT_LOCATION}/workloadIdentityPools/${PRIMUS_WORKLOAD_IDENTITY_POOL}/*" \
  --role=roles/iam.workloadIdentityUser