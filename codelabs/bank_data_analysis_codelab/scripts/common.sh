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
  gcloud config set project ${1} > /dev/null
  if [[ $? -eq 0 ]]; then
    echo "Project is set to ${1} successfully."
  else
    err "Failed to set project to ${1}."
  fi
}

#######################################
# Creates cloud storage bucket.
# Globals:
#   None
# Arguments:
#   Storage bucket name
#######################################
create_storage_bucket() {
  gsutil ls | grep ${1}
  if [[ $? -eq 0 ]]; then
    echo "Storage bucket ${1} already exists. Skipping the creation of new storage bucket ..."
  else
    echo "Storage bucket ${1} doesn't exists. Creating new storage bucket ${1} ..."
    gsutil mb gs://$1
    if [[ $? -eq 0 ]]; then
      echo "Storage bucket ${1} is created successfully."
    else
      err "Failed to create a storage bucket ${1}."
    fi
  fi
}

#######################################
# Deletes cloud storage bucket.
# Globals:
#   None
# Arguments:
#   Storage bucket name
#######################################
delete_storage_bucket() {
  gsutil ls | grep ${1}
  if [[ $? -eq 0 ]]; then
    echo "Deleting the storage bucket ${1}..."
    gsutil rm -r gs://$1
    if [[ $? -eq 0 ]]; then
      echo "Storage bucket ${1} is deleted successfully."
    else
      err "Failed to delete a storage bucket ${1}."
    fi
  else
    echo "Storage bucket ${1} doesn't exists. Skipping the deletion of storage bucket ${1} ..."
  fi
}

#######################################
# Creates KMS keyring.
# Globals:
#   None
# Arguments:
#   Keyring name
#   Location
#######################################
create_kms_keyring() {
  gcloud kms keyrings describe ${1} --location=${2} | grep ${1}
  if [[ $? -eq 0 ]]; then
    echo "Keyring ${1} already exists. Skipping the creation of new keyring ..."
  else
    echo "Keyring ${1} doesn't exists. Creating new keyring ${1} ..."
    gcloud kms keyrings create ${1} --location=${2}
    if [[ $? -eq 0 ]]; then
      echo "KMS keyring ${1} is created successully."
    else
      err "Failed to create a KMS keyring ${1}."
    fi
  fi
}

#######################################
# Creates KMS key.
# Globals:
#   None
# Arguments:
#   Key name
#   Keyring name
#   Location
#######################################
create_kms_encryption_key() {
  gcloud kms keys describe ${1} --keyring=${2} --location=${3} | grep ${1}
  if [[ $? -eq 0 ]]; then
    echo "Key ${1} for keyring ${2} already exists. Skipping the creation of new key ..."
  else
    echo "Key ${1} doesn't exists for keyring ${2}. Creating new key ${1} ..."
    gcloud kms keys create ${1} --location=${3} --keyring=${2} --purpose=encryption
    if [[ $? -eq 0 ]]; then
      echo "KMS key ${1} is created succesfully."
    else
      err "Failed to create a KMS key ${1}."
    fi
  fi
}


#######################################
# Deletes KMS key.
# Globals:
#   None
# Arguments:
#   Key name
#   Keyring name
#   Location
#######################################
destroy_kms_key() {
  gcloud kms keys describe ${1} --keyring=${2} --location=${3} | grep "ENABLED"
  if [[ $? -eq 0 ]]; then
    gcloud kms keys versions destroy 1 --key ${1} --keyring ${2} --location ${3}
    if [[ $? -eq 0 ]]; then
      echo "Key ${1} is deleted successfully."
    else
      err "Failed to delete a key ${1}."
    fi
  else
    echo "Key ${1} doesn't exist. Skipping the deletion of the key ${1}..."
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
  local sa_name="$1"
  local project_id="$2" # Accept the project ID as the second argument.

  # Construct the full, unique service account email address.
  local sa_email="${sa_name}@${project_id}.iam.gserviceaccount.com"

  # Check if the service account already exists IN THE SPECIFIED PROJECT.
  # Note the addition of the --project flag.
  gcloud iam service-accounts describe "${sa_email}" --project="${project_id}" >/dev/null 2>&1
  
  if [[ $? -eq 0 ]]; then
    echo "Service-account ${sa_email} already exists in project ${project_id}. Skipping creation."
  else
    echo "Creating service-account ${sa_name} in project ${project_id}..."
    # Create the service account IN THE SPECIFIED PROJECT.
    gcloud iam service-accounts create "${sa_name}" --display-name="${sa_name}" --project="${project_id}"
    
    if [[ $? -eq 0 ]]; then
      echo "Service-account ${sa_email} is created successfully."
    else
      echo "Error: Failed to create service-account ${sa_name} in project ${project_id}." >&2
      return 1
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
  gcloud iam service-accounts list | grep ${1}
  if [[ $? -eq 0 ]]; then
    echo "Deleting service-account ${1}..."
    gcloud iam service-accounts delete ${1} --quiet
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
# Creates a workload identity pool.
# Globals:
#   None
# Arguments:
#   Name of workload identity Pool
#   Location
#######################################
create_workload_identity_pool() {
  if [[ "${#1}" -lt 4 || "${#1}" -gt 32 ]]; then
    echo "Error: Workload identity pool name '${1}' must be between 4 and 32 characters long." >&2
    return 1
  fi

  gcloud iam workload-identity-pools describe ${1} --location=${2} | grep ${1}
  if [[ $? -eq 0 ]]; then
    echo "Workload Identity Pool ${1} already exists. Skipping the creation of new workload-idenity-pool ..."
  else
    echo "Creating workload identity pool ${1} ..."
    gcloud iam workload-identity-pools create ${1} --location ${2}
    if [[ $? -eq 0 ]]; then
      echo "Workload identity pool ${1} is created successfully."
    else
      err "Failed to create workload identity pool ${1}."
    fi
  fi
}

#######################################
# Deletes a workload identity pool.
# Globals:
#   None
# Arguments:
#   Name of workload identity Pool
#   Location
#######################################
delete_workload_identity_pool() {
  gcloud iam workload-identity-pools describe ${1} --location=${2} | grep "ACTIVE"
  if [[ $? -eq 0 ]]; then
    echo "Deleting workload-idenity-pool ${1}..."
    gcloud iam workload-identity-pools delete ${1} --location=${2} --quiet
    if [[ $? -eq 0 ]]; then
      echo "Workload identity pool ${1} is deleted successfully."
    else
      err "Failed to delete workload identity pool ${1}."
    fi
  else
    echo "Workload identity pool ${1} doesn't exist. Skipping the deletion of workload identity pool ${1} ..."
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
  gcloud artifacts repositories list --location=${2} | grep ${1}
  if [[ $? -eq 0 ]]; then
    echo "Artifact Registry ${1} already exists. Skipping the creation of new artifact registry ..."
  else
    echo "Creating new artifact registry ${1} ..."
    gcloud artifacts repositories create ${1} --repository-format=docker --location=${2}
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

#######################################
# Deletes the Virtual Machine.
# Globals:
#   None
# Arguments:
#   Name of VM
#   Zone of VM
#   Project ID under which VM was created
#######################################
delete_vm() {
  gcloud compute instances list --project ${3} | grep ${1}
  if [[ $? -eq 0 ]]; then
    echo "Deleting the workload VM ${1}..."
    gcloud compute instances delete ${1} --zone ${2} --quiet
    if [[ $? -eq 0 ]]; then
      echo "Workload VM ${1} is deleted successfully."
    else
      err "Failed to delete workload VM ${1}."
    fi
  else
    echo "Workload VM ${1} doesn't exist in zone ${2}. Skipping the deletion of workload VM ${1} ..."
  fi
}


#######################################
# Function to get confirmation for given message.
# Globals:
#   None
# Arguments:
#   Confirmation message
#######################################
get_confirmation() {
  local confirmation_message="$1"
  local confirmed=false

  while true; do
    read -p "${confirmation_message} (yes/no)" answer
    case $answer in
      [Yy]*)
        confirmed=true
        break
        ;;
      [Nn]*)
        confirmed=false
        break
        ;;
      *) echo "Please answer yes or no.";;
    esac
  done

  echo "$confirmed"
}
