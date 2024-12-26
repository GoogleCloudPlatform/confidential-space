package signedcontainer

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/GoogleCloudPlatform/confidential-space/server/signedcontainer/internal/convert"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinksig "github.com/tink-crypto/tink-go/v2/signature"
)

type ImageSignature struct {
	Payload   []byte
	Signature []byte
	Alg       signingAlgorithm
}

const maxSignatureCount = 300

type VerifyResult struct {
	Verified []*ImageSignature
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

	validSigs := make([]*ImageSignature, numSignatures)
	validationErrs := make([]error, numSignatures)

	// Perform signature verification.
	var wg sync.WaitGroup
	for i, sig := range signatures {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := verifySignature(imageDigest, sig); err != nil {
				validationErrs[i] = err
			} else {
				validSigs[i] = sig
			}
		}()
	}
	wg.Wait()

	var sigs []*ImageSignature
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

// verifySignature performs the following operations to verify a container image signature:
// 1. Parses the signature payload to get the attached public key and signing algorithm.
// 2. Verifies if payload contains the expected workload image digest.
// 3. Verifies if the given container image signature is valid using Tink and returns error if the signature verification failed.
func verifySignature(imageDigest string, sig *ImageSignature) error {
	if sig == nil {
		return errors.New("container image signature is nil")
	}

	payload, err := unmarshalAndValidate(sig.Payload)
	if err != nil {
		return fmt.Errorf("failed to unmarshal payload: %v", err)
	}

	publicKey, err := payload.publicKey()
	if err != nil {
		return err
	}

	sigAlg, err := payload.sigAlg()
	if err != nil {
		return err
	}

	if payload.Critical.Image.DockerManifestDigest != imageDigest {
		return errors.New("payload docker manifest digest does not match the running workload image digest")
	}

	// Create a public keyset handle from the given PEM-encoded public key and signing algorithm.
	publicKeysetHandle, err := createPublicKeysetHandle(publicKey, sigAlg)
	if err != nil {
		return fmt.Errorf("failed to read public keyset: %v", err)
	}

	// Retrieve the Verifier primitive from publicKeysetHandle.
	verifier, err := tinksig.NewVerifier(publicKeysetHandle)
	if err != nil {
		return fmt.Errorf("failed to create Tink signature verifier: %v", err)
	}

	if err = verifier.Verify(sig.Signature, sig.Payload); err != nil {
		return fmt.Errorf("failed to verify signature: %v", err)
	}
	return nil
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
