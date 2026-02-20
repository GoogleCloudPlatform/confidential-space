#!/bin/bash

# This prevents pushing old/bad images if the build fails.
set -e 

# This ensures 'docker build .' finds the Dockerfile sitting next to this script.
cd "$(dirname "$0")"


# Set to appropriate variables
# 1. Set Variables
# export PROJECT_ID=""
# export LOCATION=""
# export REPOSITORY=""
# export IMAGE_NAME=""

# Generate Timestamp
export IMAGE_TAG="v-$(date +%Y%m%d-%H%M%S)"

# Construct URIs
export IMAGE_URI="${LOCATION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}/${IMAGE_NAME}:${IMAGE_TAG}"
export LATEST_URI="${LOCATION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}/${IMAGE_NAME}:latest"

# 2. Set gcloud project
gcloud config set project ${PROJECT_ID}

# 3. Configure Docker authentication
gcloud auth configure-docker ${LOCATION}-docker.pkg.dev

# 4. Build the Docker Image
echo "Building image in directory: $(pwd)..."
docker build -t ${IMAGE_NAME} .

# 5. Tag the Docker Image
echo "Tagging image as ${IMAGE_TAG}..."
docker tag ${IMAGE_NAME}:latest ${IMAGE_URI}
docker tag ${IMAGE_NAME}:latest ${LATEST_URI}

# 6. Push the Image
echo "Pushing images to Artifact Registry..."
docker push ${IMAGE_URI}
docker push ${LATEST_URI}

echo "Image push complete."
echo "  Specific Tag: ${IMAGE_URI}"
echo "  Latest Tag:   ${LATEST_URI}"