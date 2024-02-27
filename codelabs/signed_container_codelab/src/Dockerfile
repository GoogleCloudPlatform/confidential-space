FROM alpine:latest

WORKDIR /test

COPY workload /test

ENTRYPOINT ["/test/workload"]

LABEL "tee.launch_policy.allow_cmd_override"="true"

CMD []