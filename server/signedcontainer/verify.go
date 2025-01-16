package signedcontainer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/GoogleCloudPlatform/confidential-space/server/signedcontainer/internal/convert"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinksig "github.com/tink-crypto/tink-go/v2/signature"
)

const (
	principalTagClaimDelimiter = "="
)

type ImageSignature struct {
	Payload   []byte
	Signature []byte
}

const maxSignatureCount = 300

type VerifiedSignature struct {
	KeyID     string `json:"key_id,omitempty"`
	Signature string `json:"signature,omitempty"`
	Alg       string `json:"signature_algorithm,omitempty"`
}

type VerifyResult struct {
	Verified []*VerifiedSignature
	Errors   []error
}

// Verify attempts to verify the provided signatures with imageDigest and returns a VerifyResults
// object, which contains successfully verified signatures and the errors that arose from verification errors.
func Verify(imageDigest string, signatures []*ImageSignature) (*VerifyResult, error) {
	numSignatures := len(signatures)
	if numSignatures == 0 {
		return &VerifyResult{}, nil
	} else if numSignatures > maxSignatureCount {
		return &VerifyResult{}, fmt.Errorf("got %v signatures, should be less than the limit %d", numSignatures, maxSignatureCount)
	}

	validSigs := make([]*VerifiedSignature, numSignatures)
	validationErrs := make([]error, numSignatures)

	// Perform signature verification.
	var wg sync.WaitGroup
	for i, sig := range signatures {
		wg.Add(1)
		go func(index int, s *ImageSignature) {
			defer wg.Done()
			verified, err := verifySignature(imageDigest, s)
			if err != nil {
				validationErrs[index] = err
			} else {
				validSigs[index] = verified
			}
		}(i, sig)
	}
	wg.Wait()

	var sigs []*VerifiedSignature
	for _, sig := range validSigs {
		if sig != nil {
			sigs = append(sigs, sig)
		}
	}

	var errs []error
	for _, err := range validationErrs {
		if err != nil {
			errs = append(errs, err)
		}
	}

	return &VerifyResult{sigs, errs}, nil

}

var encoding = base64.StdEncoding

// computeKeyID computes a hexadecimal fingerprint for a public key using SHA256.
// This will generate a keyID that aligns with this openssl command:
// openssl pkey -pubin -in public_key.pem -outform DER | openssl sha256
func computeKeyID(pemBytes []byte) (string, error) {
	derBlock, rest := pem.Decode(pemBytes)
	if derBlock == nil {
		return "", errors.New("could not decode public key bytes as PEM")
	}
	if len(rest) > 0 {
		return "", errors.New("unexpected trailing data in key file")
	}
	// Use sha256 to compute the fingerprint on the DER bytes.
	fingerprint := sha256.Sum256(derBlock.Bytes)
	return hex.EncodeToString(fingerprint[:]), nil
}

// verifySignature performs the following operations to verify a container image signature:
// 1. Parses the signature payload to get the attached public key and signing algorithm.
// 2. Verifies if payload contains the expected workload image digest.
// 3. Verifies if the given container image signature is valid using Tink and returns error if the signature verification failed.
func verifySignature(imageDigest string, sig *ImageSignature) (*VerifiedSignature, error) {
	if sig == nil {
		return nil, errors.New("container image signature is nil")
	}

	payload, err := unmarshalAndValidate(sig.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %v", err)
	}

	publicKey, err := payload.publicKey()
	if err != nil {
		return nil, err
	}

	sigAlg, err := payload.sigAlg()
	if err != nil {
		return nil, err
	}

	if payload.Critical.Image.DockerManifestDigest != imageDigest {
		return nil, errors.New("payload docker manifest digest does not match the running workload image digest")
	}

	// Create a public keyset handle from the given PEM-encoded public key and signing algorithm.
	publicKeysetHandle, err := createPublicKeysetHandle(publicKey, sigAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to read public keyset: %v", err)
	}

	// Retrieve the Verifier primitive from publicKeysetHandle.
	verifier, err := tinksig.NewVerifier(publicKeysetHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to create Tink signature verifier: %v", err)
	}

	if err = verifier.Verify(sig.Signature, sig.Payload); err != nil {
		return nil, fmt.Errorf("failed to verify signature: %v", err)
	}

	keyID, err := computeKeyID(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute keyID: %v", err)
	}

	return &VerifiedSignature{
		KeyID:     keyID,
		Signature: encoding.EncodeToString(sig.Signature),
		Alg:       sigAlg.string(),
	}, nil
}

// createPublicKeysetHandle takes in the given PEM-encoded public key and creates a public keyset handle based on the signing algorithm.
func createPublicKeysetHandle(publicKey []byte, sigAlg signingAlgorithm) (*keyset.Handle, error) {
	switch sigAlg {
	case ecdsa_p256_sha256:
		return convert.PemToECDSAP256Sha256WithDEREncodingKeysetHandle(publicKey)
	case rsasaa_pkcs1v15_sha256:
		return convert.PemToRsaSsaPkcs1Sha256KeysetHandle(publicKey)
	case rsassa_pss_sha256:
		return convert.PemToRsaSsaPssSha256KeysetHandle(publicKey)
	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %v", sigAlg)
	}
}

// FilterByKeyIDs returns the elements in 'signatures' with key IDs present in 'kids'.
// If kids is nil or empty, an empty list will be returned.
func FilterByKeyIDs(signatures []*VerifiedSignature, allowedKeyIDs []string) []string {
	// Add keyIDs to sets to remove duplicates.
	keyIdsFromClaims := map[string]bool{}
	for _, imageSigClaim := range signatures {
		keyIdsFromClaims[imageSigClaim.KeyID] = true
	}

	keyIdsSet := map[string]bool{}
	for _, goodKeyID := range allowedKeyIDs {
		if ok, _ := keyIdsFromClaims[goodKeyID]; ok {
			keyIdsSet[goodKeyID] = true
		}
	}

	// Only add the claim if there are any valid matches.
	if len(keyIdsSet) > 0 {
		keyIds := []string{}
		for k := range keyIdsSet {
			keyIds = append(keyIds, k)
		}
		// Normalize the keyIDs by sorting in ascending order before concatenating them.
		slices.Sort(keyIds)
		return []string{strings.Join(keyIds, principalTagClaimDelimiter)}
	}

	return nil
}
