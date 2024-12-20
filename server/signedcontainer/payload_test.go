package signedcontainer

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const pubKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCNEi/TiRoeS29nnSCTGX61+Z/3
6mKZmEoC81cFAYSV5f+K6oR7dwqz14wCJSNleCLLGHYfGSeWIimcfzwK6Ar93RJm
+k1wjGBmAZawd1AkIWRAXW7TzRPbO30xSpcnQ1M1bZTyjXioEDkCuB0DLpHj2gc7
q/hY7zZO8rnRN1xzTwIDAQAB
-----END PUBLIC KEY-----`

var (
	encodedPublicKey = unpaddedEncoding.EncodeToString([]byte(pubKey))
	testPayload      = &Payload{
		Critical: Critical{
			Identity: Identity{
				DockerReference: "us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base",
			},
			Image: Image{
				DockerManifestDigest: "sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba",
			},
			Type: criticalType,
		},
	}
)

func TestUnmarshalPayload(t *testing.T) {
	testCases := []struct {
		name         string
		payloadBytes []byte
		wantPayload  *Payload
		wantPass     bool
	}{
		{
			name:         "valid format",
			payloadBytes: []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":null}`),
			wantPayload:  testPayload,
			wantPass:     true,
		},
		{
			name:         "invalid format",
			payloadBytes: []byte(`{"invalid payload format": "invalid"}`),
			wantPayload:  nil,
			wantPass:     false,
		},
		{
			name:         "invalid critical type",
			payloadBytes: []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"invalid type"},"optional":null}`),
			wantPayload:  nil,
			wantPass:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotPayload, err := unmarshalAndValidate(tc.payloadBytes)
			if got := err == nil; got != tc.wantPass {
				t.Errorf("UnmarshalPayload() did not return expected error, got %v, but want %v", got, tc.wantPass)
			}
			if !cmp.Equal(gotPayload, tc.wantPayload) {
				t.Errorf("UnmarshalPayload() did not return expected payload, got %v, but want %v", gotPayload, tc.wantPayload)
			}
		})
	}
}

func TestPublicKey(t *testing.T) {
	invalidPEMKey := unpaddedEncoding.EncodeToString([]byte("invalid pem key"))
	testCases := []struct {
		name          string
		annotations   map[string]any
		wantPublicKey []byte
		wantPass      bool
	}{
		{
			name:          "cosign payload PublicKey() success",
			annotations:   map[string]any{publicKey: encodedPublicKey},
			wantPublicKey: []byte(pubKey), // PEM-encoded byte slide of public key
			wantPass:      true,
		},
		{
			name:          "cosign payload PublicKey() failed with no public key found",
			annotations:   nil,
			wantPublicKey: nil,
			wantPass:      false,
		},
		{
			name:          "cosign payload PublicKey() failed with invalid base64 encoded public key",
			annotations:   map[string]any{publicKey: "invalid base64 encoded public key"},
			wantPublicKey: nil,
			wantPass:      false,
		},
		{
			name:          "cosign payload PublicKey() failed with invalid PEM formatted public key",
			annotations:   map[string]any{publicKey: invalidPEMKey},
			wantPublicKey: nil,
			wantPass:      false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testPayload.Optional = tc.annotations
			gotPublicKey, err := testPayload.PublicKey()
			if err != nil && tc.wantPass {
				t.Errorf("PublicKey() did not return expected error for test case %v: got %v, but want nil", tc.name, err)
			}
			if !bytes.Equal(gotPublicKey, tc.wantPublicKey) {
				t.Errorf("PublicKey() did not return expected key for test case %v: got %v, but want %v", tc.name, gotPublicKey, tc.wantPublicKey)
			}
		})
	}
}

func TestSigAlg(t *testing.T) {
	testCases := []struct {
		annotations map[string]any
		expected    SigningAlgorithm
	}{
		{
			annotations: map[string]any{sigAlg: "RSASSA_PSS_SHA256"},
			expected:    RSASSA_PSS_SHA256,
		},
		{
			annotations: map[string]any{sigAlg: "RSASSA_PKCS1V15_SHA256"},
			expected:    RSASSA_PKCS1V15_SHA256,
		},
		{
			annotations: map[string]any{sigAlg: "ECDSA_P256_SHA256"},
			expected:    ECDSA_P256_SHA256,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.annotations[sigAlg].(string), func(t *testing.T) {
			testPayload.Optional = tc.annotations
			gotSigAlg, err := testPayload.SigAlg()
			if err != nil {
				t.Errorf("SigAlg() returned error %v", err)
			}
			if gotSigAlg != tc.expected {
				t.Errorf("SigAlg() did not return expected algoithm: got %v, but want %v", gotSigAlg, tc.expected)
			}
		})
	}

}

func TestSigAlgError(t *testing.T) {

	testCases := []struct {
		name        string
		annotations map[string]any
		expected    SigningAlgorithm
	}{
		{
			name:        "cosign payload SigAlg() failed with no signing algorithm found",
			annotations: nil,
			expected:    UNSPECIFIED,
		},
		{
			name:        "cosign payload SigAlg() failed with unsupported signing algorithm",
			annotations: map[string]any{sigAlg: "unsupported signing algorithm"},
			expected:    UNSPECIFIED,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testPayload.Optional = tc.annotations
			gotSigAlg, err := testPayload.SigAlg()
			if err == nil {
				t.Error("SigAlg() returned successfully, expected error", err)
			}
			if gotSigAlg != tc.expected {
				t.Errorf("SigAlg() did not return expected algoithm: got %v, want %v", gotSigAlg, tc.expected)
			}
		})
	}
}
