#!/bin/bash
#
# Creates artifact repository and workload image. It also publishes the workload image to artifact repository.

source config_env.sh
source common.sh

PARENT_DIR=$(dirname ${PWD})
PRIMUS_PROJECT_NUMBER=$(gcloud projects describe ${PRIMUS_PROJECT_ID} --format="value(projectNumber)")
SECUNDUS_PROJECT_NUMBER=$(gcloud projects describe ${SECUNDUS_PROJECT_ID} --format="value(projectNumber)")
IMAGE_REFERENCE=${PRIMUS_PROJECT_REPOSITORY_REGION}-docker.pkg.dev/${PRIMUS_PROJECT_ID}/${PRIMUS_ARTIFACT_REPOSITORY}/${WORKLOAD_IMAGE_NAME}:${WORKLOAD_IMAGE_TAG}

set_gcp_project ${PRIMUS_PROJECT_ID}

create_artifact_repository ${PRIMUS_ARTIFACT_REPOSITORY} ${PRIMUS_PROJECT_REPOSITORY_REGION}

gcloud auth configure-docker ${PRIMUS_PROJECT_REPOSITORY_REGION}-docker.pkg.dev

echo "Updating workload code with required resource names ..."
./generate_workload_code.sh
sed -i'' "s/PRIMUS_INPUT_STORAGE_BUCKET/${PRIMUS_INPUT_STORAGE_BUCKET}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/PRIMUS_PROJECT_ID/${PRIMUS_PROJECT_ID}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/PRIMUS_ENC_KEYRING/${PRIMUS_ENC_KEYRING}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/PRIMUS_ENC_KEY/${PRIMUS_ENC_KEY}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/PRIMUS_SERVICE_ACCOUNT/${PRIMUS_SERVICE_ACCOUNT}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/PRIMUS_WORKLOAD_IDENTITY_POOL/${PRIMUS_WORKLOAD_IDENTITY_POOL}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/PRIMUS_WIP_PROVIDER/${PRIMUS_WIP_PROVIDER}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/PRIMUS_PROJECT_NUMBER/${PRIMUS_PROJECT_NUMBER}/" ${PARENT_DIR}/src/workload.go

sed -i'' "s/SECUNDUS_INPUT_STORAGE_BUCKET/${SECUNDUS_INPUT_STORAGE_BUCKET}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/SECUNDUS_PROJECT_ID/${SECUNDUS_PROJECT_ID}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/SECUNDUS_ENC_KEYRING/${SECUNDUS_ENC_KEYRING}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/SECUNDUS_ENC_KEY/${SECUNDUS_ENC_KEY}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/SECUNDUS_SERVICE_ACCOUNT/${SECUNDUS_SERVICE_ACCOUNT}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/SECUNDUS_WORKLOAD_IDENTITY_POOL/${SECUNDUS_WORKLOAD_IDENTITY_POOL}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/SECUNDUS_WIP_PROVIDER/${SECUNDUS_WIP_PROVIDER}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/SECUNDUS_PROJECT_NUMBER/${SECUNDUS_PROJECT_NUMBER}/" ${PARENT_DIR}/src/workload.go

echo "Building the workload go binary ..."
cd ${PARENT_DIR}/src
go mod init workload && go mod tidy
CGO_ENABLED=0 go build workload.go

echo "Building the workload docker image ..."
docker build . -t ${IMAGE_REFERENCE}
cd ${PARENT_DIR}/scripts

echo "Pushing the workload docker image to artifact registry ${PRIMUS_ARTIFACT_REPOSITORY} ..."
docker push ${IMAGE_REFERENCE}

echo "Granting roles/artifactregistry.reader role to workload service account ${WORKLOAD_SERVICE_ACCOUNT} ..."
gcloud artifacts repositories add-iam-policy-binding ${PRIMUS_ARTIFACT_REPOSITORY} \
  --project=${PRIMUS_PROJECT_ID} \
  --role=roles/artifactregistry.reader \
  --location=${PRIMUS_PROJECT_REPOSITORY_REGION} \
  --member="serviceAccount:${WORKLOAD_SERVICE_ACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com"