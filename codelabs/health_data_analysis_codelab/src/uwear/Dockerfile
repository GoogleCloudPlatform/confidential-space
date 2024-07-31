FROM alpine:latest

WORKDIR /test

COPY workload /test
COPY phi_sleep_data /test
COPY opa_validation_values.json /test
COPY confidential_space_root.pem /test

ENTRYPOINT ["/test/workload"]

LABEL "tee.launch_policy.allow_cmd_override"="true"
LABEL "tee.launch_policy.allow_env_override"="remote_ip_addr"
LABEL "tee.launch_policy.log_redirect"="always"

CMD []