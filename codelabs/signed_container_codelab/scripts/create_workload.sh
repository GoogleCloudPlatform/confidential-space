#!/bin/bash
#
# Creates the workload.

source config_env.sh
source common.sh

PARENT_DIR=$(dirname ${PWD})
PRIMUS_PROJECT_NUMBER=$(gcloud projects describe ${PRIMUS_PROJECT_ID} --format="value(projectNumber)")
IMAGE_REFERENCE=${SECUNDUS_PROJECT_REPOSITORY_REGION}-docker.pkg.dev/${SECUNDUS_PROJECT_ID}/${SECUNDUS_ARTIFACT_REPOSITORY}/${WORKLOAD_IMAGE_NAME}:${WORKLOAD_IMAGE_TAG}

set_gcp_project ${SECUNDUS_PROJECT_ID}
create_artifact_repository ${SECUNDUS_ARTIFACT_REPOSITORY} ${SECUNDUS_PROJECT_REPOSITORY_REGION}

if ! gcloud auth configure-docker us-docker.pkg.dev; then
  fatal "Failed to authenticate to docker artifact registry."
fi

echo "Updating workload code with required resource names ..."
./generate_workload_code.sh
sed -i'' "s/PRIMUS_INPUT_STORAGE_BUCKET/${PRIMUS_INPUT_STORAGE_BUCKET}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/PRIMUS_PROJECT_ID/${PRIMUS_PROJECT_ID}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/PRIMUS_ENC_KEYRING/${PRIMUS_ENC_KEYRING}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/PRIMUS_ENC_KEY/${PRIMUS_ENC_KEY}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/PRIMUS_SERVICEACCOUNT/${PRIMUS_SERVICEACCOUNT}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/PRIMUS_WORKLOAD_IDENTITY_POOL/${PRIMUS_WORKLOAD_IDENTITY_POOL}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/PRIMUS_WIP_PROVIDER/${PRIMUS_WIP_PROVIDER}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/PRIMUS_PROJECT_NUMBER/${PRIMUS_PROJECT_NUMBER}/" ${PARENT_DIR}/src/workload.go

echo "Building the go binary ..."
cd ${PARENT_DIR}/src
go mod init workload && go mod tidy
if ! CGO_ENABLED=0 go build workload.go; then
  fatal "Failed to build binary of the workload."
fi

echo "Building the workload docker image ..."
if ! docker build . -t ${IMAGE_REFERENCE}; then
  fatal "Failed to build workload docker image ${IMAGE_REFERENCE}."
fi
cd ${PARENT_DIR}/scripts

echo "Pushing workload docker image to artifact registry ${SECUNDUS_ARTIFACT_REPOSITORY} ..."
if ! docker push ${IMAGE_REFERENCE}; then
  fatal "Failed to publish workload docker image ${IMAGE_REFERENCE} to ${SECUNDUS_ARTIFACT_REPOSITORY}."
fi

echo "Granting roles/artifactregistry.reader role to workload service account ${WORKLOAD_SERVICEACCOUNT} ..."
if ! gcloud artifacts repositories add-iam-policy-binding ${SECUNDUS_ARTIFACT_REPOSITORY} \
  --project=${SECUNDUS_PROJECT_ID} \
  --role=roles/artifactregistry.reader \
  --location=${SECUNDUS_PROJECT_REPOSITORY_REGION} \
  --member="serviceAccount:${WORKLOAD_SERVICEACCOUNT}@${SECUNDUS_PROJECT_ID}.iam.gserviceaccount.com"; then
  err "Failed to grant roles/artifactregistry.reader role to workload service account ${WORKLOAD_SERVICEACCOUNT}"
fi