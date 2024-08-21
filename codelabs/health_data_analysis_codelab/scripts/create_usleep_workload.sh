#!/bin/bash
#
# Creates artifact repository and workload image. It also publishes the workload image to artifact repository.

source config_env.sh
source common.sh
source create_workload.sh

create_workload "$USLEEP_PROJECT_ID" "$USLEEP_PROJECT_REPOSITORY_REGION" "$USLEEP_ARTIFACT_REPOSITORY" "$USLEEP_WORKLOAD_IMAGE_NAME" "$USLEEP_WORKLOAD_IMAGE_TAG" "$USLEEP_WORKLOAD_SERVICE_ACCOUNT" "usleep"
