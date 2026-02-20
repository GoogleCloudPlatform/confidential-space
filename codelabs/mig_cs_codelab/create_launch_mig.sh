#!/bin/bash

source config_env.sh

# Configuration Variables
MACHINE_TYPE="n2d-standard-2" # SEV is supported on N2D
SERVICE_ACCOUNT="${CURRENT_WORKLOAD_SERVICE_ACCOUNT}@${CURRENT_PROJECT_ID}.iam.gserviceaccount.com"
CONTAINER_IMAGE="${CURRENT_PROJECT_REPOSITORY_REGION}-docker.pkg.dev/${CURRENT_PROJECT_ID}/${CURRENT_ARTIFACT_REPOSITORY}/${CURRENT_WORKLOAD_IMAGE_NAME}:${CURRENT_WORKLOAD_IMAGE_TAG}"

# 1. Create the Confidential Space Instance Template
echo "Creating instance template '${TEMPLATE_NAME}'..."
echo "Using service account '${SERVICE_ACCOUNT}' ..."

gcloud compute instance-templates create "${TEMPLATE_NAME}" \
  --project="${CURRENT_PROJECT_ID}" \
  --machine-type="${MACHINE_TYPE}" \
  --confidential-compute-type=SEV \
  --shielded-secure-boot \
  --maintenance-policy=MIGRATE \
  --scopes=cloud-platform \
  --image-project=confidential-space-images \
  --image-family=confidential-space-debug \
  --service-account="${SERVICE_ACCOUNT}" \
  --metadata="^~^tee-image-reference=${CONTAINER_IMAGE}~tee-container-log-redirect=true"

# 2. Create the Managed Instance Group (MIG)
echo "Creating Managed Instance Group '${CURRENT_MIG_NAME}'..."
gcloud compute instance-groups managed create "${CURRENT_MIG_NAME}" \
    --size 3 \
    --template "${TEMPLATE_NAME}" \
    --zone "${CURRENT_PROJECT_ZONE}"

# 3. Fetch Project Number
echo "Fetching Project Number for ${CURRENT_PROJECT_ID}..."
PROJECT_NUMBER=$(gcloud projects describe "${CURRENT_PROJECT_ID}" --format="value(projectNumber)")

# Check if PROJECT_NUMBER was fetched successfully
if [ -z "${PROJECT_NUMBER}" ]; then
  echo "Error: Could not fetch Project Number for ${CURRENT_PROJECT_ID}."
  exit 1
fi
echo "Project Number found: ${PROJECT_NUMBER}"

# 4. Grant Compute Engine Service Agent role to the service account
# This is often needed for features like autoscaling, autohealing, etc.
# NOTE: This step might fail if you don't have 'resourcemanager.projects.setIamPolicy' permission.
echo "Adding IAM policy binding for ${SERVICE_ACCOUNT}..."
gcloud projects add-iam-policy-binding "${CURRENT_PROJECT_ID}" \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/compute.serviceAgent"
echo "IAM policy binding added."

gcloud projects add-iam-policy-binding "${CURRENT_PROJECT_ID}" \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/artifactregistry.reader"
echo "IAM policy artifact registry reader binding added."


# Create Health Check that checks to see if port 22 is healthy
gcloud compute health-checks create tcp ${HEALTH_CHECK_NAME} \
  --port 22 \
  --check-interval 30s \
  --healthy-threshold 1 \
  --timeout 10s \
  --unhealthy-threshold 3 \
  --global

# Create Firewall Rule to allow health checks to the MIG

gcloud compute firewall-rules create ${ALLOW_HEALTH_CHECK_FIREWALL_RULE_NAME} \
    --allow tcp:22 \
    --source-ranges 130.211.0.0/22,35.191.0.0/16 \
    --network default \
    --project="${CURRENT_PROJECT_ID}"

# Update the MIG with the Health Check

gcloud compute instance-groups managed update "${CURRENT_MIG_NAME}" \
    --health-check "${HEALTH_CHECK_NAME}" \
    --initial-delay 60 \
    --zone "${CURRENT_PROJECT_ZONE}"


gcloud compute instance-groups managed set-autoscaling ${CURRENT_MIG_NAME} \
    --max-num-replicas 5 \
    --target-cpu-utilization 0.80 \
    --cool-down-period 90 \
    --zone ${CURRENT_PROJECT_ZONE}


