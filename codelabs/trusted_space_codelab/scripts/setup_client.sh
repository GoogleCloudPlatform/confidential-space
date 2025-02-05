#!/bin/bash
#
# Creates required cloud resources for workload client.

source config_env.sh
source common.sh

PARENT_DIR=$(dirname "${PWD}")

echo "Creating workload client's service-account ${CLIENT_SERVICEACCOUNT} ..."
create_service_account "${CLIENT_SERVICEACCOUNT}"

echo "Granting KMS decryptor role to the service-account ${CLIENT_SERVICEACCOUNT} ..."
gcloud kms keys add-iam-policy-binding \
  projects/"${PRIMUS_PROJECT_ID}"/locations/"${PRIMUS_PROJECT_LOCATION}"/keyRings/"${PRIMUS_ENC_KEYRING}"/cryptoKeys/"${PRIMUS_ENC_KEY}" \
    --member=serviceAccount:"${CLIENT_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com \
    --role=roles/cloudkms.cryptoKeyDecrypter

echo "Granting KMS encryptor role to the service-account ${CLIENT_SERVICEACCOUNT} ..."
gcloud kms keys add-iam-policy-binding \
  projects/"${PRIMUS_PROJECT_ID}"/locations/"${PRIMUS_PROJECT_LOCATION}"/keyRings/"${PRIMUS_ENC_KEYRING}"/cryptoKeys/"${PRIMUS_ENC_KEY}" \
    --member=serviceAccount:"${CLIENT_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com \
    --role=roles/cloudkms.cryptoKeyEncrypter

echo "Creating workload client VM ${CLIENT_VM} ..."
gcloud compute instances create "${CLIENT_VM}" \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --zone="${PRIMUS_PROJECT_ZONE}" \
  --boot-disk-size=100GB \
  --scopes=cloud-platform \
  --service-account=${CLIENT_SERVICEACCOUNT}@${PRIMUS_PROJECT_ID}.iam.gserviceaccount.com

echo "Waiting for ${CLIENT_VM} to be ready for SSH connection..."
wait_for_vm_ssh_connection "${CLIENT_VM}" "${PRIMUS_PROJECT_ZONE}" "${PRIMUS_PROJECT_ID}"

echo "Updating client code with required resource names ..."
cp "${PARENT_DIR}"/src/client/sample_inference_client.py "${PARENT_DIR}"/src/client/inference_client.py
INFERENCE_SERVER_IP=$(gcloud compute instances describe "${WORKLOAD_VM}" --format='get(networkInterfaces[0].networkIP)' --zone="${PRIMUS_PROJECT_ZONE}")
sed -i'' "s/INFERENCE_SERVER_IP_VALUE/"${INFERENCE_SERVER_IP}"/" "${PARENT_DIR}"/src/client/inference_client.py
sed -i'' "s/PRIMUS_PROJECT_ID_VALUE/"${PRIMUS_PROJECT_ID}"/" "${PARENT_DIR}"/src/client/inference_client.py
sed -i'' "s/PRIMUS_KEY_ID_VALUE/"${PRIMUS_ENC_KEY}"/" "${PARENT_DIR}"/src/client/inference_client.py
sed -i'' "s/PRIMUS_KEYRING_VALUE/"${PRIMUS_ENC_KEYRING}"/" "${PARENT_DIR}"/src/client/inference_client.py
sed -i'' "s/PRIMUS_PROJECT_LOCATION_VALUE/"${PRIMUS_PROJECT_LOCATION}"/" "${PARENT_DIR}"/src/client/inference_client.py

echo "Copying client code to client VM ..."
gcloud compute scp "${PARENT_DIR}"/src/client/inference_client.py "${CLIENT_VM}":~/ --zone="${PRIMUS_PROJECT_ZONE}"
gcloud compute scp "${PARENT_DIR}"/src/client/requirements.txt "${CLIENT_VM}":~/ --zone="${PRIMUS_PROJECT_ZONE}"

echo "Installing required dependencies for client ..."
gcloud compute ssh "${CLIENT_VM}" --zone="${PRIMUS_PROJECT_ZONE}" --command="
  sudo apt-get update
  sudo apt-get install -y python3 python3-venv
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
"

echo "Client VM is created and setup is complete. You can now SSH into the client VM: gcloud compute ssh ${CLIENT_VM} --zone=${PRIMUS_PROJECT_ZONE}"