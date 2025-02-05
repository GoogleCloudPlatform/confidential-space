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
	// sigAlgURL is the key of the signing algorithm attached to the cosign-generated payload.
	sigAlgURL = "dev.cosignproject.cosign/sigalg"
)

type signingAlgorithm int

const (
	// Unspecified signing algorithm.
	unspecified = 0
	// RSASSA-PSS with a SHA256 digest.
	rsassaPssSha256 = 1
	// RSASSA-PKCS1 v1.5 with a SHA256 digest.
	rsasaaPkcs1v15Sha256 = 2
	// ECDSA on the P-256 Curve with a SHA256 digest.
	ecdsaP256Sha256 = 3
)

func (s signingAlgorithm) string() string {
	switch s {
	case unspecified:
		return "SIGNING_ALGORITHM_UNSPECIFIED"
	case rsassaPssSha256:
		return "RSASSA_PSS_SHA256"
	case rsasaaPkcs1v15Sha256:
		return "RSASSA_PKCS1V15_SHA256"
	case ecdsaP256Sha256:
		return "ECDSA_P256_SHA256"
	}

	return "SIGNING_ALGORITHM_UNSPECIFIED"
}

var unpaddedEncoding = base64.RawStdEncoding

// payload follows the simple signing format specified in
// https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md#simple-signing
type payload struct {
	Critical critical       `json:"critical"`
	Optional map[string]any `json:"optional"` // Optional represents optional metadata about the image, and its value shouldn't contain any "=" signs.
}

// critical contains data critical to correctly evaluating the validity of a signature.
type critical struct {
	Identity identity `json:"identity"`
	Image    image    `json:"image"`
	Type     string   `json:"type"`
}

// identity identifies the claimed identity of the image.
type identity struct {
	// This field is ignored for cosign semantics as it does not contain either a tag or digest for the image.
	DockerReference string `json:"docker-reference"`
}

// image identifies the container image this signature applies to.
type image struct {
	DockerManifestDigest string `json:"docker-manifest-digest"`
}

// publicKey retrieves the PEM-encoded public key from the `optional` field of the payload.
func (p *payload) publicKey() ([]byte, error) {
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

var signingAlgorithmValue = map[string]signingAlgorithm{
	"SIGNING_ALGORITHM_UNSPECIFIED": unspecified,
	"RSASSA_PSS_SHA256":             rsassaPssSha256,
	"RSASSA_PKCS1V15_SHA256":        rsasaaPkcs1v15Sha256,
	"ECDSA_P256_SHA256":             ecdsaP256Sha256,
}

// sigAlg retrieves the signing algorithm from the `optional` field of the payload.
func (p *payload) sigAlg() (signingAlgorithm, error) {
	alg, ok := p.Optional[sigAlgURL].(string)
	if !ok {
		return unspecified, fmt.Errorf("signing algorithm not found in the Optional field of payload: %v", p)
	}
	algVal, ok := signingAlgorithmValue[alg]
	if !ok || algVal == unspecified {
		return unspecified, fmt.Errorf("unsupported signing algorithm: %s", alg)
	}
	return algVal, nil
}

// UnmarshalAndValidate unmarshals a payload from JSON and performs checks on the payload.
func unmarshalAndValidate(data []byte) (*payload, error) {
	var pl payload
	if err := json.Unmarshal(data, &pl); err != nil {
		return nil, err
	}
	if pl.Critical.Type != criticalType {
		return nil, fmt.Errorf("unknown critical type for Cosign signature payload: %s", pl.Critical.Type)
	}
	return &pl, nil
}
