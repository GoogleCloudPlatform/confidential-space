#!/bin/bash

protoc -I. \
  -I$(go list -mod=readonly -m -f "{{.Dir}}" github.com/google/go-tpm-tools) \
  -I$(go list -mod=readonly -m -f "{{.Dir}}" github.com/google/go-tpm-tools)/proto \
  -I`go list -mod=readonly -m -f "{{.Dir}}" github.com/google/go-sev-guest` \
  -I`go list -mod=readonly -m -f "{{.Dir}}" github.com/google/go-tdx-guest` \
  -I/usr/local/include \
  --go_out=. \
  --go_opt=module=github.com/GoogleCloudPlatform/confidential-space/server/proto \
  google_tdx_tcb.proto image_database.proto platform_rims.proto shared.proto