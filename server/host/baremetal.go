// Package host provides functions for verifying host attestation.
package host

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"

	"github.com/google/go-eventlog/cel"
	"github.com/google/go-eventlog/extract"
	"github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/platform-attestation/titan/dice/titandice"
	"github.com/google/platform-attestation/titan/measurements"

	csextract "github.com/GoogleCloudPlatform/confidential-space/server/extract"
	hostcel "github.com/GoogleCloudPlatform/confidential-space/server/host/coscel"
	attestpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	tpmattestpb "github.com/google/go-tpm-tools/proto/attest"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	tpmquote "github.com/google/go-tpm-tools/quote"
)

const (
	// See https://api.trustedservices.intel.com/documents/Intel_SGX_PCK_Certificate_CRL_Spec-1.5.pdf.
	cpuPIIDSize = 16
)

// VerifyOpts contains the options for verifying the attestation.
type VerifyOpts struct {
	// The TPM hash algorithm to use to verify attestations.
	HashAlgo tpm2.TPMAlgID

	TitanValidationOpts *titandice.ValidateScribeCertificateChainOptions

	Nonce []byte
}

// VerifyAttestation verifies the attestation and returns the Google Bare Metal state.  This should
// only be used for attestations without workload claims.
func VerifyAttestation(attestation *attestpb.HostAttestation, opts *VerifyOpts) (*attestpb.HostACOSState, error) {
	gmesState, attestedCosState, err := VerifyAttestationWithWorkloadClaims(attestation, opts)
	if err != nil {
		return nil, err
	}
	if attestedCosState != nil {
		return nil, fmt.Errorf("workload claims are present in the attestation, but were not expected.  To verify attestations with workload claims, use VerifyAttestationWithWorkloadClaims instead")
	}
	return gmesState, err
}

// VerifyAttestationWithWorkloadClaims verifies the attestation and returns the Google Bare Metal
// state and the AttestedCosState (or nil if no workload claims are present in PCR 19).
func VerifyAttestationWithWorkloadClaims(attestation *attestpb.HostAttestation, opts *VerifyOpts) (*attestpb.HostACOSState, *tpmattestpb.AttestedCosState, error) {
	if opts == nil {
		return nil, nil, fmt.Errorf("verify opts is nil")
	}

	// Validate Titan endorsement.
	titanPubKey, err := validateTitanEndorsement(attestation.GetTpmQuote().GetEndorsement().GetTitanEndorsement(), opts.TitanValidationOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate Titan endorsement: %v", err)
	}

	var quote *attestpb.TpmQuote_SignedQuote
	for _, q := range attestation.GetTpmQuote().GetQuotes() {
		if q.GetHashAlgorithm() == uint32(opts.HashAlgo) {
			quote = q
			break
		}
	}

	if quote == nil {
		return nil, nil, fmt.Errorf("no quote found with matching hash algorithm: %v", opts.HashAlgo)
	}

	if err := tpmquote.Verify(toProtoQuote(quote), titanPubKey, opts.Nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to verify quote: %v", err)
	}

	pcrBank, err := createPCRBank(quote)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create PCR bank: %v", err)
	}

	gmesState, cosState, err := verifyEventLogs(attestation.GetTpmQuote(), pcrBank)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify and extract state: %v", err)
	}

	// Verify warm reset NV certification.
	nvCert := attestation.GetAuxAttestation().GetSignedNvs()
	if len(nvCert) == 0 {
		return nil, nil, fmt.Errorf("no NV certifications found")
	}
	if len(nvCert) > 1 {
		return nil, nil, fmt.Errorf("multiple NV certifications found, expected 1")
	}

	gmesState.WarmResetCount, err = measurements.VerifyWarmResetNVIndex(nvCert[0], opts.Nonce, titanPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract warm reset count: %v", err)
	}

	return gmesState, cosState, nil
}

func createPCRBank(pcrs *attestpb.TpmQuote_SignedQuote) (register.PCRBank, error) {
	tcgHash := state.HashAlgo(pcrs.GetHashAlgorithm())
	cryptoHashAlg, err := tcgHash.CryptoHash()
	if err != nil {
		return register.PCRBank{}, err
	}

	pcrRegs := make([]register.PCR, 0)
	for pcrIndex, digest := range pcrs.GetPcrValues() {
		pcrRegs = append(pcrRegs, register.PCR{
			Index:     int(pcrIndex),
			Digest:    digest,
			DigestAlg: cryptoHashAlg,
		})
	}

	return register.PCRBank{TCGHashAlgo: tcgHash, PCRs: pcrRegs}, nil
}

func parseCEL(rawEventLog []byte, register register.PCRBank) ([]byte, *tpmattestpb.AttestedCosState, error) {
	if len(rawEventLog) == 0 {
		return nil, nil, nil
	}

	decodedCEL, err := cel.DecodeToCEL(bytes.NewBuffer(rawEventLog))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode CEL: %v", err)
	}

	if err := decodedCEL.Replay(register); err != nil {
		return nil, nil, fmt.Errorf("failed to replay CEL: %v", err)
	}

	var cpupiid []byte
	seenSeparator := false
	for i, record := range decodedCEL.Records() {
		if record.Index != hostcel.UserspacePCRIdx {
			return nil, nil, fmt.Errorf("unexpected CEL record index: %d", record.Index)
		}

		// After the host LaunchSeparator, Dual RoT attestations append guest workload COS
		// records (Type 80, verified below via VerifiedCOSState). Ignore non-host records
		// here, but reject any additional host COS events (Type 82) after the separator.
		if seenSeparator {
			if hostcel.IsCOSTLV(record.Content) {
				return nil, nil, fmt.Errorf("found additional host COS events after separator at position %d", i)
			}
			continue
		}

		cosTLV, err := hostcel.ParseToCOSTLV(record.Content)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse COS TLV: %v", err)
		}

		if err := cel.VerifyDigests(cosTLV, record.Digests); err != nil {
			return nil, nil, fmt.Errorf("failed to verify digests: %v", err)
		}

		switch cosTLV.EventType {
		case hostcel.LaunchSeparatorType:
			seenSeparator = true
		case hostcel.CPUPIIDType:
			if len(cpupiid) != 0 {
				return nil, nil, fmt.Errorf("found duplicate CPUPIID events")
			}
			if len(cosTLV.EventContent) != cpuPIIDSize {
				return nil, nil, fmt.Errorf("invalid CPUPIID event length: %v", len(cosTLV.EventContent))
			}
			cpupiid = cosTLV.EventContent
		default:
			return nil, nil, fmt.Errorf("unknown COS event type: %v", cosTLV.EventType)
		}
	}

	if !seenSeparator {
		return nil, nil, fmt.Errorf("no separator event found")
	}

	cosState, err := csextract.VerifiedCOSState(decodedCEL, uint8(cel.PCRType), csextract.Options{
		PopulateGpuDeviceState: true,
		HostPCR:                true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract workload COS state: %v", err)
	}

	return cpupiid, cosState, nil
}

func validateTitanEndorsement(endorsement *attestpb.TpmAttestationEndorsement_TitanEndorsement, opts *titandice.ValidateScribeCertificateChainOptions) (crypto.PublicKey, error) {
	if endorsement == nil {
		return nil, fmt.Errorf("titan endorsement is nil")
	}

	if opts == nil {
		return nil, fmt.Errorf("titan validation opts is nil")
	}

	validator, err := titandice.NewValidator(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create Titan validator: %v", err)
	}

	certChain, err := titandice.ParseTitanDiceScribeCertificateChain(endorsement.GetDiceCertChain())
	if err != nil {
		return nil, fmt.Errorf("failed to parse Titan DICE certificate chain: %v", err)
	}

	if err := titandice.ValidateScribeCertificateChain(certChain, validator); err != nil {
		return nil, fmt.Errorf("failed to validate Titan DICE certificate chain: %v", err)
	}

	ekCert, err := titandice.ParseEKCertificate(endorsement.GetEkCert())
	if err != nil {
		return nil, fmt.Errorf("failed to parse EK certificate: %v", err)
	}

	// expectFirmwareLimited indicates the Alias Key is bound to a specific firmware version.
	if _, err := titandice.ValidateEKCertificate(ekCert, &certChain.AliasKeyCertificate, true /* expectFirmwareLimited */); err != nil {
		return nil, fmt.Errorf("failed to validate EK certificate: %v", err)
	}

	return titandice.ECDSAPublicKey(ekCert.PublicKey), nil
}

func parseEKCertificate(data []byte) (*titandice.EKCertificate, error) {
	ekc := &titandice.EKCertificate{}
	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.LittleEndian, &ekc.Header); err != nil {
		return nil, fmt.Errorf("failed to read EKCertificate header: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &ekc.PublicKey); err != nil {
		return nil, fmt.Errorf("failed to read EKCertificate public key: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &ekc.Signature); err != nil {
		return nil, fmt.Errorf("failed to read EKCertificate signature: %v", err)
	}
	return ekc, nil
}

func toProtoQuote(quote *attestpb.TpmQuote_SignedQuote) *tpmpb.Quote {
	return &tpmpb.Quote{
		Quote:  quote.GetTpmsAttest(),
		RawSig: quote.GetTpmtSignature(),
		Pcrs: &tpmpb.PCRs{
			Hash: tpmpb.HashAlgo(quote.GetHashAlgorithm()),
			Pcrs: quote.GetPcrValues(),
		},
	}
}

func verifyEventLogs(tpmQuote *attestpb.TpmQuote, pcrBank register.PCRBank) (*attestpb.HostACOSState, *tpmattestpb.AttestedCosState, error) {
	events, err := tcg.ParseAndReplay(tpmQuote.GetPcclientBootEventLog(), pcrBank.MRs(), tcg.ParseOpts{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse and replay boot event log: %v", err)
	}

	// Event Log Extraction.
	cryptoHashAlg, err := pcrBank.TCGHashAlgo.CryptoHash()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get crypto hash algorithm: %v", err)
	}

	gmesState, err := extract.GMESState(cryptoHashAlg, events)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract GMES state: %v", err)
	}

	// Extract CPUPIID and optional workload COS state.
	cpupiid, cosState, err := parseCEL(tpmQuote.GetCelLaunchEventLog(), pcrBank)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CEL: %v", err)
	}

	return &attestpb.HostACOSState{
		Gmes:    gmesState,
		CpuPiid: cpupiid,
	}, cosState, nil
}
