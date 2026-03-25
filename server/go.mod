module github.com/GoogleCloudPlatform/confidential-space/server

go 1.24.0

toolchain go1.24.13

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/golang/glog v1.2.2
	github.com/google/go-cmp v0.7.0
	github.com/google/go-configfs-tsm v0.3.3-0.20240919001351-b4b5b84fdcbc
	github.com/google/go-eventlog v0.0.3-0.20260305053119-5cd85087f9f9
	github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d
	github.com/google/go-tpm v0.9.6
	github.com/google/go-tpm-tools v0.4.9-0.20260325175049-22911efba9e5
	github.com/tink-crypto/tink-go/v2 v2.2.1-0.20241120130117-c41ea0ed393b
	google.golang.org/api v0.213.0
	google.golang.org/protobuf v1.36.11
)

require (
	cloud.google.com/go/auth v0.13.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.6 // indirect
	cloud.google.com/go/compute/metadata v0.6.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/go-sev-guest v0.14.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/s2a-go v0.1.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.4 // indirect
	github.com/googleapis/gax-go/v2 v2.14.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.54.0 // indirect
	go.opentelemetry.io/otel v1.29.0 // indirect
	go.opentelemetry.io/otel/metric v1.29.0 // indirect
	go.opentelemetry.io/otel/trace v1.29.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/oauth2 v0.24.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241209162323-e6fa225c2576 // indirect
	google.golang.org/grpc v1.67.1 // indirect
)
