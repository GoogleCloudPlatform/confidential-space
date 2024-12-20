package signedcontainer

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	// criticalType is the value of `critical.type` in a simple signing format payload specified in
	// https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md#simple-signing
	criticalType = "cosign container image signature"
	// publicKey is the key of the public key for signature verification attached to the cosign-generated payload.
	publicKey = "dev.cosignproject.cosign/pub"
	// sigAlg is the key of the signing algorithm attached to the cosign-generated payload.
	sigAlg = "dev.cosignproject.cosign/sigalg"
)

type SigningAlgorithm int

const (
	// Unspecified signing algorithm.
	UNSPECIFIED = 0
	// RSASSA-PSS with a SHA256 digest.
	RSASSA_PSS_SHA256 = 1
	// RSASSA-PKCS1 v1.5 with a SHA256 digest.
	RSASSA_PKCS1V15_SHA256 = 2
	// ECDSA on the P-256 Curve with a SHA256 digest.
	ECDSA_P256_SHA256 = 3
)

func (s SigningAlgorithm) String() string {
	switch s {
	case UNSPECIFIED:
		return "SIGNING_ALGORITHM_UNSPECIFIED"
	case RSASSA_PSS_SHA256:
		return "RSASSA_PSS_SHA256"
	case RSASSA_PKCS1V15_SHA256:
		return "RSASSA_PKCS1V15_SHA256"
	case ECDSA_P256_SHA256:
		return "ECDSA_P256_SHA256"
	}

	return "SIGNING_ALGORITHM_UNSPECIFIED"
}

var unpaddedEncoding = base64.RawStdEncoding

// Payload follows the simple signing format specified in
// https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md#simple-signing
type Payload struct {
	Critical Critical       `json:"critical"`
	Optional map[string]any `json:"optional"` // Optional represents optional metadata about the image, and its value shouldn't contain any "=" signs.
}

// Critical contains data critical to correctly evaluating the validity of a signature.
type Critical struct {
	Identity Identity `json:"identity"`
	Image    Image    `json:"image"`
	Type     string   `json:"type"`
}

// Identity identifies the claimed identity of the image.
type Identity struct {
	// This field is ignored for cosign semantics as it does not contain either a tag or digest for the image.
	DockerReference string `json:"docker-reference"`
}

// Image identifies the container image this signature applies to.
type Image struct {
	DockerManifestDigest string `json:"docker-manifest-digest"`
}

// PublicKey retrieves the PEM-encoded public key from the `optional` field of the payload.
func (p *Payload) PublicKey() ([]byte, error) {
	publicKey, ok := p.Optional[publicKey].(string)
	if !ok {
		return nil, fmt.Errorf("public key not found in the Optional field of payload: %v", p)
	}

	// Decode the unpadded base64 encoding public key.
	publicKeyBytes, err := unpaddedEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key string as base64 [%v]: %v", publicKey, err)
	}

	// Check if the retrieved public key is PEM formatted.
	if block, _ := pem.Decode(publicKeyBytes); block == nil {
		return nil, errors.New("could not decode public key bytes as PEM")
	}
	return publicKeyBytes, nil
}

var signingAlgorithm_value = map[string]SigningAlgorithm{
	"SIGNING_ALGORITHM_UNSPECIFIED": UNSPECIFIED,
	"RSASSA_PSS_SHA256":             RSASSA_PSS_SHA256,
	"RSASSA_PKCS1V15_SHA256":        RSASSA_PKCS1V15_SHA256,
	"ECDSA_P256_SHA256":             ECDSA_P256_SHA256,
}

// SigAlg retrieves the signing algorithm from the `optional` field of the payload.
func (p *Payload) SigAlg() (SigningAlgorithm, error) {
	alg, ok := p.Optional[sigAlg].(string)
	if !ok {
		return UNSPECIFIED, fmt.Errorf("signing algorithm not found in the Optional field of payload: %v", p)
	}
	algVal, ok := signingAlgorithm_value[alg]
	if !ok || algVal == UNSPECIFIED {
		return UNSPECIFIED, fmt.Errorf("unsupported signing algorithm: %s", alg)
	}
	return algVal, nil
}

// UnmarshalAndValidate unmarshals a payload from JSON and performs checks on the payload.
func unmarshalAndValidate(data []byte) (*Payload, error) {
	var payload Payload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	if payload.Critical.Type != criticalType {
		return nil, fmt.Errorf("unknown critical type for Cosign signature payload: %s", payload.Critical.Type)
	}
	return &payload, nil
}
