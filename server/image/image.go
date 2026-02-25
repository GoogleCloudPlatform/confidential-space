// Package image provides functions for validating confidential space images.
package image

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/GoogleCloudPlatform/confidential-space/server/image/data"

	rimpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/image_database"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
)

// Validate validates the machinestate against image RIMs. If successful, returns the associated golden values.
func Validate(machineState *attestpb.MachineState, imageDb *rimpb.ImageDatabase) (*rimpb.ImageDatabase_ImageGoldenEntry, error) {
	goldens, err := GetGoldenValues(machineState, imageDb)
	if err != nil {
		return nil, fmt.Errorf("failed to get golden values: %v", err)
	}

	if err := validateBaseValues(machineState.GetSecureBoot(), goldens.GetImageBaseVersion(), imageDb); err != nil {
		return nil, fmt.Errorf("image base values validation failed: %v", err)
	}

	return goldens, nil
}

// GetGoldenValues returns the golden values for the associated MachineState.
func GetGoldenValues(ms *attestpb.MachineState, imageDb *rimpb.ImageDatabase) (*rimpb.ImageDatabase_ImageGoldenEntry, error) {
	if ms == nil {
		return nil, errors.New("MachineState is nil")
	}
	if imageDb == nil {
		return nil, errors.New("ImageDB is nil")
	}
	kernelState := ms.GetLinuxKernel()
	if kernelState == nil {
		return nil, errors.New("No LinuxKernel state in MachineState")
	}
	cmdLine := NormalizeCmdLine(kernelState.GetCommandLine())
	goldens, ok := imageDb.GetGoldenValues()[cmdLine]
	if !ok {
		return nil, fmt.Errorf("kernel command line %q is not in the golden values", cmdLine)
	}

	return goldens, nil
}

// validateBaseValues checks the SecureBootState against its expected
// image base values. At this point, we have already validated the command
// line matches that of a Confidential Space Image.
// We specifically check the following:
// - SecureBoot is enabled.
// - The Secure Boot db has no hashes.
// - The Secure Boot db has exactly one certificate, which exactly matches the one expected known cert given by the image database.
// Original: http://google3/cloud/hosted/confidentialcomputing/clh/service/claims/helper.go;l=166;rcl=705972732.
func validateBaseValues(sb *attestpb.SecureBootState, imageBaseVersion uint32, imageDb *rimpb.ImageDatabase) error {
	imageBaseValues, ok := imageDb.GetImageBaseValues()[imageBaseVersion]
	if !ok {
		return fmt.Errorf("nonexistent image version %v", imageBaseVersion)
	}
	if !sb.GetEnabled() {
		return errors.New("machineState has no SecureBootState or SecureBoot is not enabled")
	}

	hashes := sb.GetDb().GetHashes()
	// Verify that hashes are empty.
	if len(hashes) > 0 {
		return fmt.Errorf("machineState DB had %v hashes, expected none", len(hashes))
	}

	// Verify that Secure Boot db and image db both have exactly one cert.
	certs := sb.GetDb().GetCerts()
	if len(certs) != 1 {
		return fmt.Errorf("machineState DB had %v certs, expected one", len(certs))
	}
	if len(imageBaseValues.GetDb().GetKnownCertificates()) != 1 {
		return fmt.Errorf("db should only have one known cert")
	}
	dbCert := imageBaseValues.GetDb().GetKnownCertificates()[0]

	// Get the known cert by DER corresponding to the image db cert.
	knownCert := knownCertificate(dbCert)
	if knownCert == nil {
		return errors.New("image DB does not have a known certificate")
	}

	// Assert the Secure Boot cert is a DER since the COS cert is not a well-known cert.
	if _, ok := certs[0].Representation.(*attestpb.Certificate_Der); !ok {
		return errors.New("Secure Boot DB certificate is not a DER certificate")
	}

	// Assert the Secure Boot cert is equal to the image db known cert (for CS, the COS cert).
	if !bytes.Equal(certs[0].GetDer(), knownCert.Raw) {
		return fmt.Errorf("machineState DB certificate did not match the DER of the expected known cert %v for base version %v",
			dbCert.String(), imageBaseVersion)
	}

	return nil
}

func knownCertificate(known rimpb.ImageDatabase_CCKnownCertificates) *x509.Certificate {
	switch known {
	case rimpb.ImageDatabase_COS_DB_V10:
		return data.COSDBv10Cert
	case rimpb.ImageDatabase_COS_DB_V20250203:
		return data.COSDBv20250203Cert
	case rimpb.ImageDatabase_COS_DB_V20251004:
		return data.COSDBv20251004Cert
	}
	return nil
}

// NormalizeCmdLine normalizes the command line by removing all ASCII whitespace and the null
// terminator at the beginning and end of the line.
func NormalizeCmdLine(s string) string {
	return strings.Trim(s, "\x00\t\n\v\f\r ")
}
