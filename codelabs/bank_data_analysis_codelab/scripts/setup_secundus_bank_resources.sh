#!/bin/bash
#
# Sets up the cloud resources for Secundus Bank (Data Collaborator, Workload Author and Workload Operator).

source config_env.sh
source common.sh

PARENT_DIR=$(dirname ${PWD})

if [ ! -z ${SECUNDUS_PROJECT_ID} ]; then
  echo "SECUNDUS_PROJECT_ID is set to ${SECUNDUS_PROJECT_ID}";
else
  echo "SECUNDUS_PROJECT_ID is not set, please set the SECUNDUS_PROJECT_ID with GCP project-id of Secundus Bank";
  exit 1;
fi

set_gcp_project ${SECUNDUS_PROJECT_ID}

echo "Creating input storage bucket ${SECUNDUS_INPUT_STORAGE_BUCKET} to store the customer data of Secundus Bank ..."
create_storage_bucket ${SECUNDUS_INPUT_STORAGE_BUCKET}

echo "Creating result storage bucket ${SECUNDUS_RESULT_STORAGE_BUCKET} to store the results of workload execution ..."
create_storage_bucket ${SECUNDUS_RESULT_STORAGE_BUCKET}

echo "Creating keyring ${SECUNDUS_ENC_KEYRING} for encryption key in KMS for Secundus Bank ..."
create_kms_keyring ${SECUNDUS_ENC_KEYRING} ${SECUNDUS_PROJECT_LOCATION}

echo "Creating encryption key ${SECUNDUS_ENC_KEY} in KMS to encrypt the customer data of Secundus Bank"
create_kms_encryption_key ${SECUNDUS_ENC_KEY} ${SECUNDUS_ENC_KEYRING} ${SECUNDUS_PROJECT_LOCATION}

echo "Encrypting the customer data file of Secundus Bank ..."
gcloud kms encrypt \
    --ciphertext-file="${PARENT_DIR}/artifacts/secundus_enc_customer_list.csv" \
    --plaintext-file="${PARENT_DIR}/artifacts/secundus_customer_list.csv" \
    --key=projects/${SECUNDUS_PROJECT_ID}/locations/${SECUNDUS_PROJECT_LOCATION}/keyRings/${SECUNDUS_ENC_KEYRING}/cryptoKeys/${SECUNDUS_ENC_KEY}

echo "Uploading the encrypted file to storage bucket ${SECUNDUS_INPUT_STORAGE_BUCKET} ..."
gsutil cp ${PARENT_DIR}/artifacts/secundus_enc_customer_list.csv gs://${SECUNDUS_INPUT_STORAGE_BUCKET}/secundus_enc_customer_list.csv

echo "Creating service-account ${SECUNDUS_SERVICE_ACCOUNT} for secundus bank ..."
create_service_account ${SECUNDUS_SERVICE_ACCOUNT}

echo "Granting KMS decryptor role to the service-account ${SECUNDUS_SERVICE_ACCOUNT}"
gcloud kms keys add-iam-policy-binding \
  projects/${SECUNDUS_PROJECT_ID}/locations/${SECUNDUS_PROJECT_LOCATION}/keyRings/${SECUNDUS_ENC_KEYRING}/cryptoKeys/${SECUNDUS_ENC_KEY} \
    --member=serviceAccount:${SECUNDUS_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com \
    --role=roles/cloudkms.cryptoKeyDecrypter

echo "Creating workload identity pool ${SECUNDUS_WORKLOAD_IDENTITY_POOL}"
create_workload_identity_pool ${SECUNDUS_WORKLOAD_IDENTITY_POOL} ${SECUNDUS_PROJECT_LOCATION}

echo "Attaching the service-account ${SECUNDUS_SERVICE_ACCOUNT} to workload identity pool ${SECUNDUS_WORKLOAD_IDENTITY_POOL}"
gcloud iam service-accounts add-iam-policy-binding ${SECUNDUS_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com \
  --member="principalSet://iam.googleapis.com/projects/"$(gcloud projects describe ${SECUNDUS_PROJECT_ID} \
    --format="value(projectNumber)")"/locations/${SECUNDUS_PROJECT_LOCATION}/workloadIdentityPools/${SECUNDUS_WORKLOAD_IDENTITY_POOL}/*" \
  --role=roles/iam.workloadIdentityUser