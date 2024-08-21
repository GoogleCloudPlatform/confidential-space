#!/bin/bash
#
# Creates artifact repository and workload image. It also publishes the workload image to artifact repository.

source config_env.sh
source common.sh

#######################################
# Creates artifact repository and workload image.
# It also publishes the workload image to artifact repository.
# Globals:
#   None
# Arguments:
#   Project ID
#   Project repository region
#   Artifact repository
#   Workload image name
#   Workload image tag
#   Workload service account
#   Workload Folder name
# Returns:
#   None
#######################################
create_workload() {
  local project_id=$1
  local project_repository_region=$2
  local artifact_repository=$3
  local workload_image_name=$4
  local workload_image_tag=$5
  local workload_service_account=$6
  local folder_name=$7

  PARENT_DIR=$(dirname "$PWD")

  PROJECT_NUMBER=$(gcloud projects describe "$project_id" --format="value(projectNumber)")

  IMAGE_REFERENCE=$project_repository_region-docker.pkg.dev/$project_id/$artifact_repository/$workload_image_name:$workload_image_tag

  set_gcp_project "$project_id"

  create_artifact_repository "$artifact_repository" "$project_repository_region"

  gcloud auth configure-docker "$project_repository_region"-docker.pkg.dev

  echo "Updating workload code with required resource names ..."

  sed -i'' "s/PROJECT_ID/$project_id/" "$PARENT_DIR"/src/"$folder_name"/workload.go
  sed -i'' "s/PROJECT_NUMBER/$PROJECT_NUMBER/" "$PARENT_DIR"/src/"$folder_name"/workload.go

  echo "Building the workload go binary ..."
  cd "$PARENT_DIR"/src/"$folder_name"
  go mod init workload && go mod tidy
  CGO_ENABLED=0 go build workload.go

  echo "Building the workload docker image ..."
  docker build . -t "$IMAGE_REFERENCE"
  cd "$PARENT_DIR"/scripts

  echo "Pushing the workload docker image to artifact registry $artifact_repository ..."
  docker push "$IMAGE_REFERENCE"

  echo "Granting roles/artifactregistry.reader role to workload service account $workload_service_account ..."
  gcloud artifacts repositories add-iam-policy-binding "$artifact_repository" \
    --project="$project_id" \
    --role=roles/artifactregistry.reader \
    --location="$project_repository_region" \
    --member="serviceAccount:$workload_service_account@$project_id.iam.gserviceaccount.com"
}
