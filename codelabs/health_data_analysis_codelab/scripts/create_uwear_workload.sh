#!/bin/bash
#
# Creates artifact repository and workload image. It also publishes the workload image to artifact repository.

source config_env.sh
source common.sh
source create_workload.sh

create_workload "$UWEAR_PROJECT_ID" "$UWEAR_PROJECT_REPOSITORY_REGION" "$UWEAR_ARTIFACT_REPOSITORY" "$UWEAR_WORKLOAD_IMAGE_NAME" "$UWEAR_WORKLOAD_IMAGE_TAG" "$UWEAR_WORKLOAD_SERVICE_ACCOUNT" "uwear"
