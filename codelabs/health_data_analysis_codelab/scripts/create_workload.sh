#!/bin/bash
#
# Creates artifact repository and workload image. It also publishes the workload image to artifact repository.

source config_env.sh
source common.sh

PARENT_DIR=$(dirname ${PWD})
UWEAR_PROJECT_NUMBER=$(gcloud projects describe ${UWEAR_PROJECT_ID} --format="value(projectNumber)")
USLEEP_PROJECT_NUMBER=$(gcloud projects describe ${USLEEP_PROJECT_ID} --format="value(projectNumber)")
IMAGE_REFERENCE=${UWEAR_PROJECT_REPOSITORY_REGION}-docker.pkg.dev/${UWEAR_PROJECT_ID}/${UWEAR_ARTIFACT_REPOSITORY}/${WORKLOAD_IMAGE_NAME}:${WORKLOAD_IMAGE_TAG}

set_gcp_project ${UWEAR_PROJECT_ID}

create_artifact_repository ${UWEAR_ARTIFACT_REPOSITORY} ${UWEAR_PROJECT_REPOSITORY_REGION}

gcloud auth configure-docker ${UWEAR_PROJECT_REPOSITORY_REGION}-docker.pkg.dev

echo "Updating workload code with required resource names ..."
./generate_workload_code.sh
sed -i'' "s/UWEAR_PROJECT_ID/${UWEAR_PROJECT_ID}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/UWEAR_PROJECT_NUMBER/${UWEAR_PROJECT_NUMBER}/" ${PARENT_DIR}/src/workload.go

sed -i'' "s/USLEEP_PROJECT_ID/${USLEEP_PROJECT_ID}/" ${PARENT_DIR}/src/workload.go
sed -i'' "s/USLEEP_PROJECT_NUMBER/${USLEEP_PROJECT_NUMBER}/" ${PARENT_DIR}/src/workload.go

echo "Building the workload go binary ..."
cd ${PARENT_DIR}/src
go mod init workload && go mod tidy
CGO_ENABLED=0 go build workload.go

echo "Building the workload docker image ..."
docker build . -t ${IMAGE_REFERENCE}
cd ${PARENT_DIR}/scripts

echo "Pushing the workload docker image to artifact registry ${UWEAR_ARTIFACT_REPOSITORY} ..."
docker push ${IMAGE_REFERENCE}

echo "Granting roles/artifactregistry.reader role to workload service account ${WORKLOAD_SERVICE_ACCOUNT} ..."
gcloud artifacts repositories add-iam-policy-binding ${UWEAR_ARTIFACT_REPOSITORY} \
  --project=${UWEAR_PROJECT_ID} \
  --role=roles/artifactregistry.reader \
  --location=${UWEAR_PROJECT_REPOSITORY_REGION} \
  --member="serviceAccount:${WORKLOAD_SERVICE_ACCOUNT}@${USLEEP_PROJECT_ID}.iam.gserviceaccount.com"