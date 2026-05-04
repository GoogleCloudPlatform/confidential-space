#!/bin/bash

# Collect include paths, only adding them if they are not empty.
INCLUDES=("-I.")

add_include() {
  local module="$1"
  local path
  path=$(go list -mod=readonly -m -f "{{.Dir}}" "$module" 2>/dev/null)
  if [ -n "$path" ]; then
    INCLUDES+=("-I$path")
    # Also add /proto subdirectory if it exists.
    if [ -d "$path/proto" ]; then
      INCLUDES+=("-I$path/proto")
    fi
  else
    echo "Warning: Module $module not found, skipping." >&2
  fi
}

add_include "github.com/google/go-tpm-tools"
add_include "github.com/google/go-eventlog"
add_include "github.com/google/go-sev-guest"
add_include "github.com/google/go-tdx-guest"

protoc "${INCLUDES[@]}" \
  -I/usr/local/include \
  --go_out=. \
  --go_opt=module=github.com/GoogleCloudPlatform/confidential-space/server/proto \
  *.proto
