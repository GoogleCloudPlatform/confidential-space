#!/bin/bash

protoc -I. --go_out=.. --go_opt=module=github.com/GoogleCloudPlatform/confidential-space/proto --experimental_allow_proto3_optional shared.proto
