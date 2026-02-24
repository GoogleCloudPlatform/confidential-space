#!/bin/bash
# Creates artifact repository and workload image. It also publishes the workload image to artifact repository.

source config_env.sh
source common.sh

#######################################
# Creates artifact repository and workload image.
# It also publishes the workload image to artifact repository.
# Globals:
#   Project ID
#   Project repository region
#   Artifact repository
#   Workload image name
#   Workload image tag
#   Workload service account
#   Workload Folder name
# Arguments:
#   None
# Returns:
#   None
#######################################



PROJECT_ID=$CURRENT_PROJECT_ID
REGION=$CURRENT_PROJECT_REPOSITORY_REGION
REPOSITORY=$CURRENT_ARTIFACT_REPOSITORY
IMAGE_NAME=$CURRENT_WORKLOAD_IMAGE_NAME
PARENT_DIR=$(dirname "$PWD")

# Generate a timestamped tag (e.g., v-20251120-103000)
TIMESTAMP_TAG="v-$(date +%Y%m%d-%H%M%S)"

# Define full Image URIs
REPO_PATH="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}"
IMAGE_URI="${REPO_PATH}/${IMAGE_NAME}:${TIMESTAMP_TAG}"
LATEST_URI="${REPO_PATH}/${IMAGE_NAME}:latest"

# 3. Setup Project & Auth
# Ensure we are targeting the correct GCP project
gcloud config set project "${PROJECT_ID}"


# Create the repo if it doesn't exist (using your common.sh function)
create_artifact_repository "${REPOSITORY}" "${REGION}"



# Configure Docker to authenticate with Artifact Registry
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet


# 4. Prepare Source Code
echo "Preparing source code..."
cd "$PARENT_DIR"/src

# 5. Build and Push
echo "Building Docker image..."
# Build with the name, no-cache to ensure fresh build
docker build --no-cache -t "${IMAGE_NAME}" . 

echo "Tagging image..."
# Tag the specific timestamp
docker tag "${IMAGE_NAME}:latest" "${IMAGE_URI}"
# Tag 'latest'
docker tag "${IMAGE_NAME}:latest" "${LATEST_URI}"

echo "Pushing images to Artifact Registry..."
docker push "${IMAGE_URI}"
docker push "${LATEST_URI}"

echo "----------------------------------------------------"
echo "Build and Push Complete!"
echo "Timestamped Tag: ${IMAGE_URI}"
echo "Latest Tag:      ${LATEST_URI}"
echo "----------------------------------------------------"