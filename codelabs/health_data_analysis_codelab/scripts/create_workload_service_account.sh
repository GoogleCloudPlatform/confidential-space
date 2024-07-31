#!/bin/bash
#
# Creates workload service-account.

source config_env.sh
source common.sh

set_gcp_project ${USLEEP_PROJECT_ID}

echo "Creating workload service-account ${USLEEP_WORKLOAD_SERVICE_ACCOUNT} under project ${USLEEP_PROJECT_ID}..."
create_service_account ${USLEEP_WORKLOAD_SERVICE_ACCOUNT}

echo "Granting roles/iam.serviceAccountUser role to workload operator ..."
if ! gcloud iam service-accounts add-iam-policy-binding ${USLEEP_WORKLOAD_SERVICE_ACCOUNT}@${USLEEP_PROJECT_ID}.iam.gserviceaccount.com \
  --member="user:$(gcloud config get-value account)" \
  --role="roles/iam.serviceAccountUser"; then
  err "Failed to grant roles/iam.serviceAccountUser role workload operator $(gcloud config get-value account) under project ${USLEEP_PROJECT_ID}."
fi

echo "Granting roles/confidentialcomputing.workloadUser to service-account $USLEEP_WORKLOAD_SERVICE_ACCOUNT} ..."
if ! gcloud projects add-iam-policy-binding ${USLEEP_PROJECT_ID} \
  --member="serviceAccount:${USLEEP_WORKLOAD_SERVICE_ACCOUNT}@${USLEEP_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/confidentialcomputing.workloadUser"; then
  err "Failed to grant roles/confidentialcomputing.workloadUser to service-account ${USLEEP_WORKLOAD_SERVICE_ACCOUNT}."
fi

echo "Granting roles/logging.logWriter to service-account ${USLEEP_WORKLOAD_SERVICE_ACCOUNT} ..."
if ! gcloud projects add-iam-policy-binding ${USLEEP_PROJECT_ID} \
  --member="serviceAccount:${USLEEP_WORKLOAD_SERVICE_ACCOUNT}@${USLEEP_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/logging.logWriter"; then
  err "Failed to grant roles/logging.logWriter to service-account ${USLEEP_WORKLOAD_SERVICE_ACCOUNT}."
fi

set_gcp_project ${UWEAR_PROJECT_ID}

echo "Creating workload service-account ${UWEAR_WORKLOAD_SERVICE_ACCOUNT} under project ${UWEAR_PROJECT_ID}..."
create_service_account ${UWEAR_WORKLOAD_SERVICE_ACCOUNT}

echo "Granting roles/iam.serviceAccountUser role to workload operator ..."
if ! gcloud iam service-accounts add-iam-policy-binding ${UWEAR_WORKLOAD_SERVICE_ACCOUNT}@${UWEAR_PROJECT_ID}.iam.gserviceaccount.com \
  --member="user:$(gcloud config get-value account)" \
  --role="roles/iam.serviceAccountUser"; then
  err "Failed to grant roles/iam.serviceAccountUser role workload operator $(gcloud config get-value account) under project ${UWEAR_PROJECT_ID}."
fi

echo "Granting roles/confidentialcomputing.workloadUser to service-account ${UWEAR_WORKLOAD_SERVICE_ACCOUNT} ..."
if ! gcloud projects add-iam-policy-binding ${UWEAR_PROJECT_ID} \
  --member="serviceAccount:${UWEAR_WORKLOAD_SERVICE_ACCOUNT}@${UWEAR_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/confidentialcomputing.workloadUser"; then
  err "Failed to grant roles/confidentialcomputing.workloadUser to service-account ${UWEAR_WORKLOAD_SERVICE_ACCOUNT}."
fi

echo "Granting roles/logging.logWriter to service-account ${UWEAR_WORKLOAD_SERVICE_ACCOUNT} ..."
if ! gcloud projects add-iam-policy-binding ${UWEAR_PROJECT_ID} \
  --member="serviceAccount:${UWEAR_WORKLOAD_SERVICE_ACCOUNT}@${UWEAR_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/logging.logWriter"; then
  err "Failed to grant roles/logging.logWriter to service-account ${UWEAR_WORKLOAD_SERVICE_ACCOUNT}."
fi