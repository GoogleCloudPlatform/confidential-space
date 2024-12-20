package signedcontainer

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
)

const (
	testPubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMLdxI5u7ON+1QzJ+njeahioIRU/V
gqLf36SUAhbJ/Qnof5HkiJfXB/cBawuddv9JfNFL4nXLNZTHfz4uBrPduw==
-----END PUBLIC KEY-----`

	// Generate a ECDSA public key by following these steps:
	// 1. Generate a ECDSA private key using:
	// openssl ecparam -name prime256v1 -genkey -noout -out ec_private.pem
	// 2. Extract a public key from the private key using:
	// openssl ec -in private.pem -pubout -out ec_public.pem
	ecdsaPubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMLdxI5u7ON+1QzJ+njeahioIRU/V
gqLf36SUAhbJ/Qnof5HkiJfXB/cBawuddv9JfNFL4nXLNZTHfz4uBrPduw==
-----END PUBLIC KEY-----`

	// Generate a RSA public key by following these steps:
	// 1. Generate a RSA private key using:
	// openssl genrsa -out rsa_private.pem 2048
	// 2. Extract a public key from the private key using:
	// openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
	rsaPubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtXmc2Ir66Wq0D2eO6+fK
I7SKJ85N6/FTsBW+i/KHQaecmpAmaatqqoSzmQ+34Ibpe6UPH+MlI19cwEYP/8Vk
MbMII9mM460jdLPUvhigJthv5nHm1htN+WPG9BiQuDkktWhOdJgZFbWtHXCEMW38
zZH6FDsnvuTW9oPDjEKNB7CpWnpbZNx50pTb2mMQZBW75W0mYuw4h++fo5Z7EpWm
N8Fg2TK/2Qu4KUSSdu8yYiZTn97AMNjoAiNFjRwWw7G+O2rOcMhuU2Gt8eieXyFm
JI6E7jgZRHtW6VddCLbchgJAXtbNOkV5cG2GLyoXq6sVJ61F70tx5VB54665SgNU
JwIDAQAB
-----END PUBLIC KEY-----`

	payloadFmt = `{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":{"dev.cosignproject.cosign/pub": "%s","dev.cosignproject.cosign/sigalg": "%s"}}`

	validImageDigest = "sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"
)

// base64-encoded signatures over byte slices of the corresponding payloads:
var base64Sigs = map[SigningAlgorithm]string{
	// openssl dgst -sign ec_private.pem -sha256 | base64
	ECDSA_P256_SHA256: "MEUCIDWVapx3r93lFmKRR3v2AzYUui2Pdur3AYSYkiicZKcEAiEAj3GC2+1JdRXxypXrUmTqtFrPxneCY3jQAdqoCDmjVx0=",
	// openssl dgst -sign rsa_private.pem -sha256 | base64
	RSASSA_PKCS1V15_SHA256: "PxShLjtQfmju/mKLtHJ5gsX1M8nlkEv2uYpKuNvVeANSrH3Px4hAOw302G2YLPaLRMcsBnLKIVL4lHr0FqqDQluVj/eJJ+PHvcmSltbLhCvw2f1ZTjt/NcgThfL5gpywgAHVXSYESettaCezWsPvRlyf6vypKMbnaO8D6gWX96hAiAFdHbTnVlpQ5rBjbyErx5NkyZhaGPOqXk6FAtZDHFy7Cg+vaq9wItZzp/7+JC7dEIRQel9xSKYUKIG4W563Q/7i8DGMg+rETOxgpBR9oco3QNev7YIuDUd++Dk3M/Wv9b1u6I9aqBdVe86TU+5Ur2nyNxw9chzhNmtdu5zTyA==",
	// openssl dgst -sign rsa_private.pem -sigopt rsa_padding_mode:pss -sha256 | base64
	RSASSA_PSS_SHA256: "egqyxSJnAqS/GJ0ryeL2RXz2xCl53ynSt2Nk09VjP20IffO3uAjMsfneJOQjOljJRzMknsp4S0yr7E+6pBIi9x3Qkcs+KTpUNMpEAtXhn/qloE1SUx/j7uTUSQBkaxnlQvwrmMup+PChDNL6aRRfzEiV/rmywAicWCS4kLtHXNFOcV3emd1t3Vzp00ywfGFKjTzFnJlyxsLjO+uEsYlpUWjGaJ4n2f0wOthEGHH02wVEYNHS5wEYpu0GbcaL7C3pdBsYfpQHZWhHTNcalLBASbQ5ienMn17ZDm0bXplEbtjd2hj+xFIy0iKD39YV94vtsA0yjIkRSiXHVCWEKKWIUA==",
}

func decodedSig(t *testing.T, alg SigningAlgorithm) []byte {
	t.Helper()

	sigBytes, err := encoding.DecodeString(base64Sigs[alg])
	if err != nil {
		t.Fatalf("encoding.DecodeString(%q) failed: %v", alg.String(), err)
	}

	return sigBytes
}

// CreateTestContainerImageSignature creates a valid container image signature.
func testSig(t *testing.T) *ImageSignature {
	t.Helper()
	// base64-encoded signature over the given payload:
	// openssl dgst -sign ec_private.pem -sha256 | base64
	base64Sig := "MEUCIDWVapx3r93lFmKRR3v2AzYUui2Pdur3AYSYkiicZKcEAiEAj3GC2+1JdRXxypXrUmTqtFrPxneCY3jQAdqoCDmjVx0="
	sigBytes, err := base64.StdEncoding.DecodeString(base64Sig)
	if err != nil {
		t.Fatalf("Error decoding base64 signature (%s): %v", base64Sig, err)
	}
	testPayloadFmt := `{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":{"dev.cosignproject.cosign/pub": "%s","dev.cosignproject.cosign/sigalg": "%s"}}`
	encodedPubKey := base64.RawStdEncoding.EncodeToString([]byte(testPubKey))
	validSig := &ImageSignature{
		Payload:   []byte(fmt.Sprintf(testPayloadFmt, encodedPubKey, "ECDSA_P256_SHA256")),
		Signature: sigBytes,
	}
	return validSig
}

func TestVerify(t *testing.T) {
	invalidSignature := &ImageSignature{
		Payload:   []byte("invalid payload"),
		Signature: []byte("invalid signature"),
	}
	validSignature := testSig(t)

	testCases := []struct {
		name                     string
		imageDigest              string
		containerImageSignatures []*ImageSignature
		expectedSignatures       []*ImageSignature
		numExpectedErrors        int
	}{
		{
			name:                     "valid signatures",
			imageDigest:              validImageDigest,
			containerImageSignatures: []*ImageSignature{validSignature},
			expectedSignatures:       []*ImageSignature{validSignature},
			numExpectedErrors:        0,
		},
		{
			name:                     "empty list of signatures",
			imageDigest:              validImageDigest,
			containerImageSignatures: []*ImageSignature{},
			expectedSignatures:       nil,
			numExpectedErrors:        0,
		},
		{
			name:                     "nil signatures",
			imageDigest:              validImageDigest,
			containerImageSignatures: nil,
			expectedSignatures:       nil,
			numExpectedErrors:        0,
		},
		{
			name:                     "invalid signatures",
			imageDigest:              validImageDigest,
			containerImageSignatures: []*ImageSignature{invalidSignature},
			expectedSignatures:       nil,
			numExpectedErrors:        1,
		},
		{
			name:                     "valid, invalid, and nil signatures",
			imageDigest:              validImageDigest,
			containerImageSignatures: []*ImageSignature{validSignature, invalidSignature, nil},
			expectedSignatures:       []*ImageSignature{validSignature},
			numExpectedErrors:        2,
		},
		{
			name:                     "mismatched image digest",
			imageDigest:              "sha256:845f77fab71033404f4cfceaa1ddb27b70c3551ceb22a5e7f4498cdda6c9daea",
			containerImageSignatures: []*ImageSignature{validSignature},
			expectedSignatures:       nil,
			numExpectedErrors:        1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotSigs, partial, err := Verify(tc.imageDigest, tc.containerImageSignatures)
			if err != nil {
				t.Fatalf("Verify(%v, %v) returned error: %v", tc.imageDigest, tc.containerImageSignatures, err)
			}
			if len(partial) != tc.numExpectedErrors {
				t.Errorf("Verify(%v, %v) did not return number of expected partial errors, got %d, want %d", tc.imageDigest, tc.containerImageSignatures, len(partial), tc.numExpectedErrors)
			}
			if diff := cmp.Diff(gotSigs, tc.expectedSignatures, protocmp.Transform()); diff != "" {
				t.Errorf("Verify(%v, %v) returned unexpected signatures diff (-want +got):\n%s", tc.imageDigest, tc.containerImageSignatures, diff)
			}
		})
	}
}

func TestVerifyWithTooManySignatures(t *testing.T) {
	signatures := make([]*ImageSignature, maxSignatureCount+1)
	_, _, err := Verify("sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba", signatures)
	if err == nil {
		t.Errorf("Verify did not return expected error, got nil, but want error")
	}
}

func TestVerifySignature(t *testing.T) {
	testCases := []struct {
		name      string
		publicKey string
		sigAlg    SigningAlgorithm
	}{
		{
			name:      "ECDSA",
			publicKey: ecdsaPubKey,
			sigAlg:    ECDSA_P256_SHA256,
		},
		{
			name:      "RSASSAPKCS1V15",
			publicKey: rsaPubKey,
			sigAlg:    RSASSA_PKCS1V15_SHA256,
		},
		{
			name:      "RSASSAPSS",
			publicKey: rsaPubKey,
			sigAlg:    RSASSA_PSS_SHA256,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encodedPubKey := unpaddedEncoding.EncodeToString([]byte(tc.publicKey))
			signature := &ImageSignature{
				Payload:   []byte(fmt.Sprintf(payloadFmt, encodedPubKey, tc.sigAlg.String())),
				Signature: decodedSig(t, tc.sigAlg),
			}
			if err := verifySignature(validImageDigest, signature); err != nil {
				t.Errorf("verifySignature() failed: %v", err)
			}
		})
	}
}

func TestVerifySignatureWithInvalidDigest(t *testing.T) {
	invalidDigest := "sha256:be2784b34b8243d0fc6b3422a358200a769ffcd51f976128982b2af51d5ca69b"
	expectErr := "payload docker manifest digest does not match the running workload image digest"

	testCases := []struct {
		name      string
		publicKey string
		sigAlg    SigningAlgorithm
	}{
		{
			name:      "ECDSA",
			publicKey: ecdsaPubKey,
			sigAlg:    ECDSA_P256_SHA256,
		},
		{
			name:      "RSASSAPKCS1V15",
			publicKey: rsaPubKey,
			sigAlg:    RSASSA_PKCS1V15_SHA256,
		},
		{
			name:      "RSASSAPSS",
			publicKey: rsaPubKey,
			sigAlg:    RSASSA_PSS_SHA256,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encodedPubKey := unpaddedEncoding.EncodeToString([]byte(tc.publicKey))
			signature := &ImageSignature{
				Payload:   []byte(fmt.Sprintf(payloadFmt, encodedPubKey, tc.sigAlg.String())),
				Signature: decodedSig(t, tc.sigAlg),
			}
			if err := verifySignature(invalidDigest, signature); !strings.Contains(err.Error(), expectErr) {
				t.Errorf("VerifyContainerImageSignature() failed: got error [%v], but want error [%v]", err.Error(), expectErr)
			}
		})
	}
}

func TestVerifySignatureWithInvalidSignature(t *testing.T) {
	expectErr := "invalid signature"

	invalidSig, err := encoding.DecodeString("aGVsbG8gd29ybGQ=") // base64-encoded "hello world"
	if err != nil {
		t.Fatalf("encoding.DecodeString() failed: %v", err)
	}

	testCases := []struct {
		name      string
		publicKey string
		sigAlg    SigningAlgorithm
	}{
		{
			name:      "ECDSA",
			publicKey: ecdsaPubKey,
			sigAlg:    ECDSA_P256_SHA256,
		},
		{
			name:      "RSASSAPKCS1V15",
			publicKey: rsaPubKey,
			sigAlg:    RSASSA_PKCS1V15_SHA256,
		},
		{
			name:      "RSASSAPSS",
			publicKey: rsaPubKey,
			sigAlg:    RSASSA_PSS_SHA256,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encodedPubKey := unpaddedEncoding.EncodeToString([]byte(tc.publicKey))
			signature := &ImageSignature{
				Payload:   []byte(fmt.Sprintf(payloadFmt, encodedPubKey, tc.sigAlg.String())),
				Signature: []byte(invalidSig),
			}
			if err := verifySignature(validImageDigest, signature); !strings.Contains(err.Error(), expectErr) {
				t.Errorf("VerifyContainerImageSignature() failed: got error [%v], but want error [%v]", err.Error(), expectErr)
			}
		})
	}
}

func TestVerifySignatureWithBadPubKey(t *testing.T) {
	mismatchedECDSA := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjzUXn0HNOwGfmR/EwrMb59sb+z
RXTSpMYm8DiHgBlQuUIuchvO4F2IrweKJjc0hh7eEn9NdCegVey/namk9cEA==
-----END PUBLIC KEY-----`

	mismatchedRSA := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7JhFuEtpszV1fOmjB5wb
Rb+vnKCjsrFuhq8ZUYwrourC3H8YKDl/FYo+ZIPXxBcQzY18WeOUt90SgvTfLsF0
AJ0pgfkJsm/9zr2kw4bPJXmboXhUiun8DoqoeTHwpdjDU7hUMFLgP/2v3EBCu68l
Ew4Hcd6VPrlPiDQarZprPN9fWUxAQmf3Z4YLDdc90GSYKCXjjUjCwvC+qTK/RGQN
Bgqrd61r4M7EZFfHukkK+iBivR/pL1yNeGFWJdeEXx9f0M/vfLkev65d2yyV136d
M1ro14r+fRG7ml15zJmlPKTU2mPVgcFDlEntp3urZqAXRqnAUaNf+NF5YiLo4EQX
SQIDAQAB
-----END PUBLIC KEY-----`

	testCases := []struct {
		name      string
		publicKey string
		sigAlg    SigningAlgorithm
		expectErr string
	}{
		{
			name:      "ECDSA with mismatched key",
			publicKey: mismatchedECDSA,
			sigAlg:    ECDSA_P256_SHA256,
			expectErr: "invalid signature",
		},
		{
			name:      "RSASSA_PKCS1V15_SHA256 with mismatched key",
			publicKey: mismatchedRSA,
			sigAlg:    RSASSA_PKCS1V15_SHA256,
			expectErr: "invalid signature",
		},
		{
			name:      "RSASSA_PSS_SHA256 with mismatched key",
			publicKey: mismatchedRSA,
			sigAlg:    RSASSA_PSS_SHA256,
			expectErr: "invalid signature",
		},
		{
			name:      "ECDSA with RSA key",
			publicKey: rsaPubKey,
			sigAlg:    ECDSA_P256_SHA256,
			expectErr: "public key is not an ECDSA public key",
		},
		{
			name:      "RSASSA_PKCS1V15_SHA256 with ECDSA key",
			publicKey: ecdsaPubKey,
			sigAlg:    RSASSA_PKCS1V15_SHA256,
			expectErr: "public key is not a RSA public key",
		},
		{
			name:      "RSASSA_PSS_SHA256 with ECDSA key",
			publicKey: ecdsaPubKey,
			sigAlg:    RSASSA_PSS_SHA256,
			expectErr: "public key is not a RSA public key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encodedPubKey := unpaddedEncoding.EncodeToString([]byte(tc.publicKey))
			signature := &ImageSignature{
				Payload:   []byte(fmt.Sprintf(payloadFmt, encodedPubKey, tc.sigAlg.String())),
				Signature: decodedSig(t, tc.sigAlg),
			}
			if err := verifySignature(validImageDigest, signature); !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("VerifyContainerImageSignature() failed: got error [%v], but want error [%v]", err.Error(), tc.expectErr)
			}
		})
	}
}

func TestCreatePublicKeysetHandle(t *testing.T) {
	testCases := []struct {
		name      string
		publicKey string
		sigAlg    SigningAlgorithm
		wantPass  bool
	}{
		{
			name:      "RSASSA_PKCS1V15_SHA256 createPublicKeyset",
			publicKey: rsaPubKey,
			sigAlg:    RSASSA_PKCS1V15_SHA256,
			wantPass:  true,
		},
		{
			name:      "RSASSA_PSS_SHA256 createPublicKeyset",
			publicKey: rsaPubKey,
			sigAlg:    RSASSA_PSS_SHA256,
			wantPass:  true,
		},
		{
			name:      "ECDSA_P256_SHA256 createPublicKeyset",
			publicKey: ecdsaPubKey,
			sigAlg:    ECDSA_P256_SHA256,
			wantPass:  true,
		},
		{
			name:      "createPublicKeyset failed with unspecified signing algorithm",
			publicKey: rsaPubKey,
			sigAlg:    UNSPECIFIED,
			wantPass:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := createPublicKeysetHandle([]byte(tc.publicKey), tc.sigAlg)
			if got := err == nil; got != tc.wantPass {
				t.Errorf("createPublicKeysetHandle() = %v, but want %v, err %v", got, tc.wantPass, err)
			}
		})
	}
}
