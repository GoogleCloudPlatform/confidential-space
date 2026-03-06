#!/bin/bash
#
# Creates workload service-account.

source config_env.sh
source common.sh

set_gcp_project "${CURRENT_PROJECT_ID}"

echo "Creating workload service-account ${CURRENT_WORKLOAD_SERVICE_ACCOUNT} under project ${CURRENT_PROJECT_ID}..."
create_service_account "${CURRENT_WORKLOAD_SERVICE_ACCOUNT}"
grant_service_account_user_role_to_workload_operator "${CURRENT_WORKLOAD_SERVICE_ACCOUNT}" "${CURRENT_PROJECT_ID}"
grant_workload_user_role_to_service_account "${CURRENT_WORKLOAD_SERVICE_ACCOUNT}" "${CURRENT_PROJECT_ID}"
grant_log_writer_role_to_service_account "${CURRENT_WORKLOAD_SERVICE_ACCOUNT}" "${CURRENT_PROJECT_ID}"

set_gcp_project "${CURRENT_PROJECT_ID}"

echo "Creating workload service-account ${CURRENT_WORKLOAD_SERVICE_ACCOUNT} under project ${CURRENT_PROJECT_ID}..."
create_service_account "${CURRENT_WORKLOAD_SERVICE_ACCOUNT}"

grant_service_account_user_role_to_workload_operator "${CURRENT_WORKLOAD_SERVICE_ACCOUNT}" "${CURRENT_PROJECT_ID}"
grant_workload_user_role_to_service_account "${CURRENT_WORKLOAD_SERVICE_ACCOUNT}" "${CURRENT_PROJECT_ID}"
grant_log_writer_role_to_service_account "${CURRENT_WORKLOAD_SERVICE_ACCOUNT}" "${CURRENT_PROJECT_ID}"
grant_run_developer_role_to_service_account "${CURRENT_WORKLOAD_SERVICE_ACCOUNT}" "${CURRENT_PROJECT_ID}"
grant_run_invoker_role_to_service_account "${CURRENT_WORKLOAD_SERVICE_ACCOUNT}" "${CURRENT_PROJECT_ID}"
grant_cloud_scheduler_admin_role_to_service_account "${CURRENT_WORKLOAD_SERVICE_ACCOUNT}" "${CURRENT_PROJECT_ID}"