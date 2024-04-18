#!/bin/bash
#
# Creates ML workload and publishes the workload docker image to artifact registry.

source config_env.sh
source common.sh

PARENT_DIR=$(dirname "${PWD}")
PRIMUS_PROJECT_NUMBER=$(gcloud projects describe "${PRIMUS_PROJECT_ID}" --format="value(projectNumber)")
SECUNDUS_PROJECT_NUMBER=$(gcloud projects describe "${SECUNDUS_PROJECT_ID}" --format="value(projectNumber)")
IMAGE_REFERENCE="${PRIMUS_PROJECT_REPOSITORY_REGION}"-docker.pkg.dev/"${PRIMUS_PROJECT_ID}"/"${PRIMUS_ARTIFACT_REPOSITORY}"/"${WORKLOAD_IMAGE_NAME}":"${WORKLOAD_IMAGE_TAG}"

set_gcp_project "${PRIMUS_PROJECT_ID}"

create_artifact_repository "${PRIMUS_ARTIFACT_REPOSITORY}" "${PRIMUS_PROJECT_REPOSITORY_REGION}"

gcloud auth configure-docker "${PRIMUS_PROJECT_REPOSITORY_REGION}"-docker.pkg.dev

echo "Updating workload code with required resource names ..."
cp "${PARENT_DIR}"/src/sample_inference_server.py "${PARENT_DIR}"/src/inference_server.py

sed -i'' "s/PRIMUS_INPUT_STORAGE_BUCKET_VALUE/"${PRIMUS_INPUT_STORAGE_BUCKET}"/" "${PARENT_DIR}"/src/inference_server.py
sed -i'' "s/PRIMUS_PROJECT_ID_VALUE/"${PRIMUS_PROJECT_ID}"/" "${PARENT_DIR}"/src/inference_server.py
sed -i'' "s/PRIMUS_SERVICEACCOUNT_VALUE/"${PRIMUS_SERVICEACCOUNT}"/" "${PARENT_DIR}"/src/inference_server.py
sed -i'' "s/PRIMUS_WORKLOAD_IDENTITY_POOL_VALUE/"${PRIMUS_WORKLOAD_IDENTITY_POOL}"/" "${PARENT_DIR}"/src/inference_server.py
sed -i'' "s/PRIMUS_WIP_PROVIDER_VALUE/"${PRIMUS_WIP_PROVIDER}"/" "${PARENT_DIR}"/src/inference_server.py
sed -i'' "s/PRIMUS_PROJECT_NUMBER_VALUE/"${PRIMUS_PROJECT_NUMBER}"/" "${PARENT_DIR}"/src/inference_server.py
sed -i'' "s/SECUNDUS_PROJECT_ID_VALUE/"${SECUNDUS_PROJECT_ID}"/" "${PARENT_DIR}"/src/inference_server.py
sed -i'' "s/SECUNDUS_PROJECT_NUMBER_VALUE/"${SECUNDUS_PROJECT_NUMBER}"/" "${PARENT_DIR}"/src/inference_server.py
sed -i'' "s/SECUNDUS_INPUT_STORAGE_BUCKET_VALUE/"${SECUNDUS_INPUT_STORAGE_BUCKET}"/" "${PARENT_DIR}"/src/inference_server.py
sed -i'' "s/SECUNDUS_RESULT_STORAGE_BUCKET_VALUE/"${SECUNDUS_RESULT_STORAGE_BUCKET}"/" "${PARENT_DIR}"/src/inference_server.py

echo "Building the workload docker image ..."
cd "${PARENT_DIR}"/src

echo "Building the workload docker image ..."
if ! docker build . -t "${IMAGE_REFERENCE}"; then
  fatal "Failed to build workload docker image "${IMAGE_REFERENCE}"."
fi

echo "Pushing workload docker image to artifact registry "${PRIMUS_ARTIFACT_REPOSITORY}" ..."
if ! docker push "${IMAGE_REFERENCE}"; then
  fatal "Failed to publish workload docker image "${IMAGE_REFERENCE}" to "${PRIMUS_ARTIFACT_REPOSITORY}"."
fi

cd "${PARENT_DIR}"/scripts

echo "Granting roles/artifactregistry.reader role to workload service account "${WORKLOAD_SERVICEACCOUNT}" ..."
if ! gcloud artifacts repositories add-iam-policy-binding "${PRIMUS_ARTIFACT_REPOSITORY}" \
  --project="${PRIMUS_PROJECT_ID}" \
  --role=roles/artifactregistry.reader \
  --location="${PRIMUS_PROJECT_REPOSITORY_REGION}" \
  --member="serviceAccount:"${WORKLOAD_SERVICEACCOUNT}"@"${SECUNDUS_PROJECT_ID}".iam.gserviceaccount.com"; then
  err "Failed to grant roles/artifactregistry.reader role to workload service account "${WORKLOAD_SERVICEACCOUNT}""
fi