FROM alpine:latest
EXPOSE 8081

WORKDIR /test

COPY workload /test
COPY server.crt /test/server.crt
COPY server.key /test/server.key

ENTRYPOINT ["/test/workload"]

LABEL "tee.launch_policy.allow_cmd_override"="true"
LABEL "tee.launch_policy.log_redirect"="always"

CMD []
