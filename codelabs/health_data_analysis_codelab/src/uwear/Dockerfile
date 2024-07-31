FROM alpine:latest

WORKDIR /test

COPY workload /test
COPY phi_sleep_data /test
COPY opa_validation_values.json /test
COPY rootCertificate.pem /test

ENTRYPOINT ["/test/workload"]

LABEL "tee.launch_policy.allow_cmd_override"="true"

CMD []