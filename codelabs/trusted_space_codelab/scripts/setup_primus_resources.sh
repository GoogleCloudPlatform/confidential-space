#!/bin/bash
#
# Sets up the cloud resources for Primus.

source config_env.sh
source common.sh

PARENT_DIR=$(dirname ${PWD})

if [ ! -z "${PRIMUS_PROJECT_ID}" ]; then
  echo "PRIMUS_PROJECT_ID is set to "${PRIMUS_PROJECT_ID}""
else
  err "PRIMUS_PROJECT_ID is not set, please set the PRIMUS_PROJECT_ID with GCP project-id of Primus."
  exit 1;
fi

set_gcp_project "${PRIMUS_PROJECT_ID}"

echo "Creating keyring ${PRIMUS_ENC_KEYRING} for encryption key in KMS ..."
create_kms_keyring "${PRIMUS_ENC_KEYRING}" "${PRIMUS_PROJECT_LOCATION}"

echo "Creating encryption key ${PRIMUS_ENC_KEY} in KMS ..."
create_kms_encryption_key "${PRIMUS_ENC_KEY}" "${PRIMUS_ENC_KEYRING}" "${PRIMUS_PROJECT_LOCATION}"

echo "Creating service-account ${PRIMUS_SERVICEACCOUNT} that has access to the prompt encryption key of Primus ..."
create_service_account "${PRIMUS_SERVICEACCOUNT}"

echo "Granting KMS decryptor role to the service-account ${PRIMUS_SERVICEACCOUNT} ..."
gcloud kms keys add-iam-policy-binding \
  projects/"${PRIMUS_PROJECT_ID}"/locations/"${PRIMUS_PROJECT_LOCATION}"/keyRings/"${PRIMUS_ENC_KEYRING}"/cryptoKeys/"${PRIMUS_ENC_KEY}" \
    --member=serviceAccount:"${PRIMUS_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com \
    --role=roles/cloudkms.cryptoKeyDecrypter

echo "Granting KMS encryptor role to the service-account ${PRIMUS_SERVICEACCOUNT} ..."
gcloud kms keys add-iam-policy-binding \
  projects/"${PRIMUS_PROJECT_ID}"/locations/"${PRIMUS_PROJECT_LOCATION}"/keyRings/"${PRIMUS_ENC_KEYRING}"/cryptoKeys/"${PRIMUS_ENC_KEY}" \
    --member=serviceAccount:"${PRIMUS_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com \
    --role=roles/cloudkms.cryptoKeyEncrypter

echo "Creating workload identity pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ..."
create_workload_identity_pool "${PRIMUS_WORKLOAD_IDENTITY_POOL}" "${PRIMUS_PROJECT_LOCATION}"

echo "Attaching the service-account ${PRIMUS_SERVICEACCOUNT} to workload identity pool ${PRIMUS_WORKLOAD_IDENTITY_POOL} ..."
gcloud iam service-accounts add-iam-policy-binding "${PRIMUS_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com \
  --member="principalSet://iam.googleapis.com/projects/"$(gcloud projects describe "${PRIMUS_PROJECT_ID}" \
    --format="value(projectNumber)")"/locations/"${PRIMUS_PROJECT_LOCATION}"/workloadIdentityPools/"${PRIMUS_WORKLOAD_IDENTITY_POOL}"/*" \
  --role=roles/iam.workloadIdentityUser