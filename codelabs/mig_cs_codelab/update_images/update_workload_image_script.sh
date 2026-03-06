#!/bin/bash
# Reboots the existing VMs to refresh the container
gcloud compute instance-groups managed rolling-action restart "${CURRENT_MIG_NAME}" \
    --project="${PROJECT_ID}" \
    --zone="${CURRENT_PROJECT_ZONE}" \
    --max-surge=1 \
    --max-unavailable=0

# Wait for the update to complete
gcloud compute instance-groups managed wait-until --stable "${CURRENT_MIG_NAME}" \
    --zone="${CURRENT_PROJECT_ZONE}" \
    --project="${CURRENT_PROJECT_ID}"