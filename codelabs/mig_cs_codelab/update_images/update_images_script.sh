#!/bin/bash

# Initialize the template
gcloud compute instance-groups managed set-instance-template "${CURRENT_MIG_NAME}" \
--template=projects/"${PROJECT_ID}"/global/instanceTemplates/"${TEMPLATE_NAME}" \
--zone="${CURRENT_PROJECT_ZONE}" \
--project="${PROJECT_ID}"

# Trigger the rolling replace
gcloud compute instance-groups managed rolling-action replace "${CURRENT_MIG_NAME}" \
    --version=template="${TEMPLATE_NAME}" \
    --project="${PROJECT_ID}" \
    --zone="${CURRENT_PROJECT_ZONE}" \
    --max-surge=1 \
    --max-unavailable=0

# Wait for the update to complete
gcloud compute instance-groups managed wait-until --version-target-reached "${CURRENT_MIG_NAME}" \
    --zone="${CURRENT_PROJECT_ZONE}" \
    --project="${PROJECT_ID}"