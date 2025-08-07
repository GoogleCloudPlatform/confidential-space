#!/bin/bash

protoc -I. -I.. -I$(go list -m -f "{{.Dir}}" github.com/google/go-tpm-tools) -I$(go list -m -f "{{.Dir}}" github.com/google/go-tpm-tools)/proto  -I$(go list -m -f "{{.Dir}}" github.com/google/go-sev-guest) -I$(go list -m -f "{{.Dir}}" github.com/google/go-tdx-guest) --go_out=.. --go_opt=module=github.com/google/confidential_space/proto   --experimental_allow_proto3_optional cs_platform_rims.proto
