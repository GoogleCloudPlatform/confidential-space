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
  echo "Setting project to $1 ..."
  gcloud config set project "$1" > /dev/null
  if [[ $? -eq 0 ]]; then
    echo "Project is set to $1 successfully."
  else
    err "Failed to set project to $1."
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
  gcloud iam service-accounts list | grep "$1"
  if [[ $? -eq 0 ]]; then
    echo "Service-account $1 already exists. Skipping the create of new service-account ..."
    return
  fi

  echo "Creating service-account $1 ..."
  gcloud iam service-accounts create "$1"
  if [[ $? -eq 0 ]]; then
    echo "Service-account $1 is created successfully."
  else
    err "Failed to create service-account $1."
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
  gcloud iam service-accounts list | grep "$1"
  if [[ $? -ne 0 ]]; then
    echo "Service-account $1 doesn't exist. Skipping the deletion of workload identity pool $1 ..."
    return
  fi

  echo "Deleting service-account $1..."
  gcloud iam service-accounts delete "$1" --quiet
  if [[ $? -eq 0 ]]; then
    echo "Service-account $1 is deleted successfully."
  else
    err "Failed to delete service-account $1."
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
  gcloud artifacts repositories list --location="$2" | grep "$1"
  if [[ $? -eq 0 ]]; then
    echo "Artifact Registry $1 already exists. Skipping the creation of new artifact registry ..."
    return
  fi

  echo "Creating new artifact registry $1 ..."
  gcloud artifacts repositories create "$1" --repository-format=docker --location="$2"
  if [[ $? -eq 0 ]]; then
    echo "Artifact registry $1 is created successfully."
  else
    err "Failed to create a artifact registry $1."
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
  gcloud artifacts repositories list --location=$2 | grep $1
  if [[ $? -ne 0 ]]; then
    echo "Artifact repository $1 doesn't exist. Skipping the deletion of $1..."
    return
  fi

  echo "Deleting an artifact repository $1 ..."
  gcloud artifacts repositories delete $1 --location=$2 --quiet
  if [[ $? -eq 0 ]]; then
    echo "Artifact repository $1 is deleted successfully."
  else
    err "Failed to delete a artifact repository $1."
  fi
}

#######################################
# Grants roles/iam.serviceAccountUser role to workload operator.
# Globals:
#   None
# Arguments:
#   Workload service account
#   Project ID
#######################################
grant_service_account_user_role_to_workload_operator() {
  local workload_service_account=$1
  local project_id=$2

  echo "Granting roles/iam.serviceAccountUser role to workload operator ..."
  if ! gcloud iam service-accounts add-iam-policy-binding "$workload_service_account"@"$project_id".iam.gserviceaccount.com \
    --member="user:$(gcloud config get-value account)" \
    --role="roles/iam.serviceAccountUser"; then
    err "Failed to grant roles/iam.serviceAccountUser role workload operator $(gcloud config get-value account) under project $project_id."
  fi
}

#######################################
# Grants roles/confidentialcomputing.workloadUser to service-account.
# Globals:
#   None
# Arguments:
#   Workload service account
#   Project ID
#######################################
grant_workload_user_role_to_service_account() {
  local workload_service_account=$1
  local project_id=$2

  echo "Granting roles/confidentialcomputing.workloadUser to service-account $workload_service_account ..."
  if ! gcloud projects add-iam-policy-binding "$project_id" \
    --member="serviceAccount:$workload_service_account@$project_id.iam.gserviceaccount.com" \
    --role="roles/confidentialcomputing.workloadUser"; then
    err "Failed to grant roles/confidentialcomputing.workloadUser to service-account $workload_service_account."
  fi
}

#######################################
# Grants roles/logging.logWriter to service-account.
# Globals:
#   None
# Arguments:
#   Workload service account
#   Project ID
#######################################
grant_log_writer_role_to_service_account() {
  local workload_service_account=$1
  local project_id=$2

  echo "Granting roles/logging.logWriter to service-account $workload_service_account ..."
  if ! gcloud projects add-iam-policy-binding "$project_id" \
    --member="serviceAccount:$workload_service_account@$project_id.iam.gserviceaccount.com" \
    --role="roles/logging.logWriter"; then
    err "Failed to grant roles/logging.logWriter to service-account $workload_service_account."
  fi
}
