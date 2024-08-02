#!/bin/bash
#
# Common utility functions and variables.


#######################################
# Prints an error message.
# Globals:
#   None
# Arguments:
#   Message
#######################################
err() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

#######################################
# Sets the GCP project.
# Globals:
#   None
# Arguments:
#   GCP Project-Id
#######################################
set_gcp_project() {
  echo "Setting project to ${1} ..."
  gcloud config set project "${1}" > /dev/null
  if [[ $? -eq 0 ]]; then
    echo "Project is set to ${1} successfully."
  else
    err "Failed to set project to ${1}."
  fi
}


#######################################
# Creates a service-account.
# Globals:
#   None
# Arguments:
#   Name of the service-account
#######################################
create_service_account() {
  gcloud iam service-accounts list | grep "${1}"
  if [[ $? -eq 0 ]]; then
    echo "Service-account ${1} already exists. Skipping the create of new service-account ..."
  else
    echo "Creating service-account ${1} ..."
    gcloud iam service-accounts create "${1}"
    if [[ $? -eq 0 ]]; then
      echo "Service-account ${1} is created successfully."
    else
      err "Failed to create service-account ${1}."
    fi
  fi
}

#######################################
# Deletes a service-account.
# Globals:
#   None
# Arguments:
#   Name of the service-account
#######################################
delete_service_account() {
  gcloud iam service-accounts list | grep "${1}"
  if [[ $? -eq 0 ]]; then
    echo "Deleting service-account ${1}..."
    gcloud iam service-accounts delete "${1}" --quiet
    if [[ $? -eq 0 ]]; then
      echo "Service-account ${1} is deleted successfully."
    else
      err "Failed to delete service-account ${1}."
    fi
  else
    echo "Service-account ${1} doesn't exist. Skipping the deletion of workload identity pool ${1} ..."
  fi
}

#######################################
# Creates an artifact repository.
# Globals:
#   None
# Arguments:
#   Name of artifact repository
#   Location of artifact repository
#######################################
create_artifact_repository() {
  gcloud artifacts repositories list --location="${2}" | grep "${1}"
  if [[ $? -eq 0 ]]; then
    echo "Artifact Registry ${1} already exists. Skipping the creation of new artifact registry ..."
  else
    echo "Creating new artifact registry ${1} ..."
    gcloud artifacts repositories create "${1}" --repository-format=docker --location="${2}"
    if [[ $? -eq 0 ]]; then
      echo "Artifact registry ${1} is created successfully."
    else
      err "Failed to create a artifact registry ${1}."
    fi
  fi
}

#######################################
# Deletes an artifact repository.
# Globals:
#   None
# Arguments:
#   Name of artifact repository
#   Location of artifact repository
#######################################
delete_artifact_repository() {
  gcloud artifacts repositories list --location=${2} | grep ${1}
  if [[ $? -eq 0 ]]; then
    echo "Deleting an artifact repository ${1} ..."
    gcloud artifacts repositories delete ${1} --location=${2} --async  --quiet
    if [[ $? -eq 0 ]]; then
      echo "Artifact repository ${1} is deleted successfully."
    else
      err "Failed to delete a artifact repository ${1}."
    fi
  else
    echo "Artifact repository ${1} doesn't exist. Skipping the deletion of ${1}..."
  fi
}