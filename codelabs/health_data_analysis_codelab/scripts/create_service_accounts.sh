#!/bin/bash
#
# Creates workload service-account.

source config_env.sh
source common.sh
source create_workload_service_account.sh

set_gcp_project "${USLEEP_PROJECT_ID}"

echo "Creating workload service-account ${USLEEP_WORKLOAD_SERVICE_ACCOUNT} under project ${USLEEP_PROJECT_ID}..."
create_service_account "${USLEEP_WORKLOAD_SERVICE_ACCOUNT}"
grant_service_account_user_role_to_workload_operator "${USLEEP_WORKLOAD_SERVICE_ACCOUNT}" "${USLEEP_PROJECT_ID}"
grant_workload_user_role_to_service_account "${USLEEP_WORKLOAD_SERVICE_ACCOUNT}" "${USLEEP_PROJECT_ID}"
grant_log_writer_role_to_service_account "${USLEEP_WORKLOAD_SERVICE_ACCOUNT}" "${USLEEP_PROJECT_ID}"

set_gcp_project "${UWEAR_PROJECT_ID}"

echo "Creating workload service-account ${UWEAR_WORKLOAD_SERVICE_ACCOUNT} under project ${UWEAR_PROJECT_ID}..."
create_service_account "${UWEAR_WORKLOAD_SERVICE_ACCOUNT}"
grant_service_account_user_role_to_workload_operator "${UWEAR_WORKLOAD_SERVICE_ACCOUNT}" "${UWEAR_PROJECT_ID}"
grant_workload_user_role_to_service_account "${UWEAR_WORKLOAD_SERVICE_ACCOUNT}" "${UWEAR_PROJECT_ID}"
grant_log_writer_role_to_service_account "${UWEAR_WORKLOAD_SERVICE_ACCOUNT}" "${UWEAR_PROJECT_ID}"