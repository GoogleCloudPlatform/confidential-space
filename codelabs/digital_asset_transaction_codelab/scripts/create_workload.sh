#!/bin/bash
#
# Creates workload.

set -uo pipefail

source config_env.sh
source common.sh

PARENT_DIR=$(dirname "${PWD}")
PRIMUS_PROJECT_NUMBER=$(gcloud projects describe "${PRIMUS_PROJECT_ID}" --format="value(projectNumber)")
IMAGE_REFERENCE="${PRIMUS_PROJECT_REPOSITORY_REGION}"-docker.pkg.dev/"${PRIMUS_PROJECT_ID}"/"${PRIMUS_ARTIFACT_REPOSITORY}"/"${WORKLOAD_IMAGE_NAME}":"${WORKLOAD_IMAGE_TAG}"

set_gcp_project "${PRIMUS_PROJECT_ID}"
create_artifact_repository "${PRIMUS_ARTIFACT_REPOSITORY}" "${PRIMUS_PROJECT_REPOSITORY_REGION}"

gcloud auth configure-docker "${PRIMUS_PROJECT_REPOSITORY_REGION}"-docker.pkg.dev
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
  --member="serviceAccount:"${WORKLOAD_SERVICEACCOUNT}"@"${PRIMUS_PROJECT_ID}".iam.gserviceaccount.com"; then
  err "Failed to grant roles/artifactregistry.reader role to workload service account "${WORKLOAD_SERVICEACCOUNT}""
fi