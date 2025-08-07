#!/bin/bash

protoc -I. -I.. --go_out=.. --go_opt=module=github.com/GoogleCloudPlatform/confidential_space/proto --experimental_allow_proto3_optional google_tdx_tcb.proto
