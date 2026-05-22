package host

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	hostcel "google3/third_party/confidential_space/server/host/coscel/coscel"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-eventlog/cel"
	"google3/third_party/golang/github_com/google/go_eventlog/v/v0/extract/gmes/gmes"
	"github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
	"google3/third_party/golang/github_com/google/go_tpm/v/v0/tpm2/tpm2"
	proto "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google3/third_party/platform_attestation/titan/dice/titandice/titandice"

	apb "google3/third_party/confidential_space/server/proto/attestation_go_proto"
	spb "github.com/google/go-eventlog/proto/state"
	tpb "github.com/google/go-tpm-tools/proto/tpm"

	_ "embed"
)

// Titan Dice test data.
var (
	// Dev test data.
	//go:embed testdata/ekc_dev.bin
	ekcDataDev []byte

	//go:embed testdata/titan_dice_cert_chain_dev.bin
	titanDiceChainDataDev []byte

	//go:embed testdata/scribe_cert_0_dev.bin
	scribeCertDataDev []byte

	//go:embed testdata/payload_key_cert_dev.bin
	payloadKeyCertDataDev []byte

	// rwSigningKeyInfoDev is an identifier for the key used to sign test certificates.
	rwSigningKeyInfoDev = titandice.KeyInfo{0x2b, 0xf4, 0x82, 0x25}

	// Prod test data.
	//go:embed testdata/scribe_cert_prod.bin
	scribeCertDataProd []byte

	//go:embed testdata/scribe_cert_2_prod.bin
	scribeCertData2Prod []byte

	//go:embed testdata/titan_quote_prod.bin
	titanQuoteDataProd []byte

	rwSigningKeyInfoProd = titandice.KeyInfo{0x47, 0x22, 0x4d, 0xc6}
)

// GMES test data.
var (
	//go:embed testdata/gmes_eventlog.bin
	gmesEventLogData []byte

	// PCR banks corresponding to the gmes_eventlog.bin.
	gmesPCRBanks = []*tpb.PCRs{
		{
			Hash: tpb.HashAlgo_SHA256,
			Pcrs: map[uint32][]byte{
				0:  decodeHex("f9540cbdaceac7ac4cf50e5559deb2a44e4f05c6f1b6721858c2023aeb85de2e"),
				17: decodeHex("c5b51103f7de2193215459e14261707827694d3a84da18b78538091f14026e08"),
				21: decodeHex("db21fa9a73a8079c141bffc828d02ba07bf643c32a43fecbb4064f0e3434457a"),
			},
		},
	}

	gmesExpectedState = &spb.GMESState{
		BmcFirmwareDigest: decodeHex("88356cd60a1f7d51441ad4466df8ebca30eab0fee284055885bc695e8ace3e65"),
		BiosDigest:        decodeHex("6aefac425621df011708809ac06922b7ff74dc7cd7cc3f32412168fe7fdffaa2"),
		HostKernelDigest:  decodeHex("dd2e9cb35cbb92943a4cfa2bf7d5975ad0a7a677e3cee2d05ca8547ae696d139"),
	}

	//go:embed testdata/cel_launch_event_log.bin
	celLaunchEventLogData []byte

	// PCR banks corresponding to the cel_launch_event_log.bin.
	celLaunchPCRBanks = []*tpb.PCRs{
		{
			Hash: tpb.HashAlgo_SHA256,
			Pcrs: map[uint32][]byte{
				hostcel.UserspacePCRIdx: decodeHex("3ed1b5e170fc70001cc427164e1784752b96faaf34241c519027fbff3ee9295a"),
			},
		},
	}

	celExpectedPIID = bytes.Repeat([]byte{0x42}, 16)
)

func decodeHex(hexStr string) []byte {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	return bytes
}

func TestVerifyEventLogs(t *testing.T) {
	tpmQuote := testTPMQuote(gmesEventLogData, nil, gmesPCRBanks, &apb.TpmAttestationEndorsement{
		Endorsement: &apb.TpmAttestationEndorsement_TitanEndorsement_{
			TitanEndorsement: &apb.TpmAttestationEndorsement_TitanEndorsement{
				DiceCertChain: titanDiceChainDataDev,
				EkCert:        ekcDataDev,
			},
		},
	})

	expectedState := &apb.HostACOSState{
		Gmes: gmesExpectedState,
	}

	state, err := verifyEventLogs(tpmQuote, convertToPCRBank(t, gmesPCRBanks[0]))
	if err != nil {
		t.Fatalf("verifyEventLogs failed: %v", err)
	}

	if !cmp.Equal(state, expectedState, protocmp.Transform()) {
		t.Errorf("got state %+v, want %+v", state, expectedState)
	}
}

func TestVerifyEventLogsWithCEL(t *testing.T) {
	tcgELData, gmesPCRs, expectedGMESState := testValidGMESLog(t)

	// Combine PCR banks from gmes and cel.
	pcrs := &tpb.PCRs{
		Hash: tpb.HashAlgo_SHA256,
		Pcrs: make(map[uint32][]byte),
	}
	for _, pcr := range []*tpb.PCRs{gmesPCRs} {
		for ind, dgst := range pcr.GetPcrs() {
			pcrs.Pcrs[ind] = dgst
		}
	}
	for _, pcr := range celLaunchPCRBanks {
		for ind, dgst := range pcr.GetPcrs() {
			pcrs.Pcrs[ind] = dgst
		}
	}

	tpmQuote := testTPMQuote(tcgELData, celLaunchEventLogData, []*tpb.PCRs{pcrs}, &apb.TpmAttestationEndorsement{
		Endorsement: &apb.TpmAttestationEndorsement_TitanEndorsement_{
			TitanEndorsement: &apb.TpmAttestationEndorsement_TitanEndorsement{
				DiceCertChain: titanDiceChainDataDev,
				EkCert:        ekcDataDev,
			},
		},
	})

	expectedState := &apb.HostACOSState{
		Gmes:    expectedGMESState,
		CpuPiid: celExpectedPIID,
	}

	state, err := verifyEventLogs(tpmQuote, convertToPCRBank(t, pcrs))
	if err != nil {
		t.Fatalf("verifyEventLogs failed: %v", err)
	}

	if !cmp.Equal(state, expectedState, protocmp.Transform()) {
		t.Errorf("got state %+v, want %+v", state, expectedState)
	}
}

func testTPMQuote(tpmEventLog []byte, launcherEventLog []byte, pcrBanks []*tpb.PCRs, endorsement *apb.TpmAttestationEndorsement) *apb.TpmQuote {
	var quotes []*apb.TpmQuote_SignedQuote
	for _, pcrBank := range pcrBanks {
		quote := &apb.TpmQuote_SignedQuote{
			HashAlgorithm: uint32(pcrBank.GetHash()),
			PcrValues:     pcrBank.GetPcrs(),
		}
		quotes = append(quotes, quote)
	}

	return &apb.TpmQuote{
		Quotes:               quotes,
		PcclientBootEventLog: tpmEventLog,
		CelLaunchEventLog:    launcherEventLog,
		Endorsement:          endorsement,
	}
}

func TestParseCPUPIID(t *testing.T) {
	pcrBank := convertToPCRBank(t, celLaunchPCRBanks[0])
	piid, err := parseCPUPIID(celLaunchEventLogData, pcrBank)
	if err != nil {
		t.Fatalf("Failed to parse PIID event: %v", err)
	}

	if !bytes.Equal(piid, celExpectedPIID) {
		t.Errorf("PIID event content does not match: got %x, want %x", hex.EncodeToString(piid), celExpectedPIID)
	}
}

func TestParseCPUPIIDErrors(t *testing.T) {
	testPIID := bytes.Repeat([]byte{0x42}, 16)

	testcases := []struct {
		name      string
		createCEL func(*testing.T) ([]byte, []byte)
		wantError string
	}{
		{
			name: "missing separator",
			createCEL: func(t *testing.T) (eventLog []byte, pcrVal []byte) {
				pcrValue := make([]byte, 32)
				testCEL := createCELRecord(t, 0, hostcel.UserspacePCRIdx, &pcrValue, hostcel.CPUPIIDType, testPIID)

				return testCEL, pcrValue
			},
			wantError: "no separator event found",
		},
		{
			name: "duplicate separator",
			createCEL: func(t *testing.T) (eventLog []byte, pcrVal []byte) {
				pcrValue := make([]byte, 32)
				testCEL := createCELRecord(t, 0, hostcel.UserspacePCRIdx, &pcrValue, hostcel.CPUPIIDType, testPIID)
				testCEL = append(testCEL, createCELRecord(t, 1, hostcel.UserspacePCRIdx, &pcrValue, hostcel.LaunchSeparatorType, nil)...)
				// Duplicate separator event should cause an error.
				testCEL = append(testCEL, createCELRecord(t, 2, hostcel.UserspacePCRIdx, &pcrValue, hostcel.LaunchSeparatorType, nil)...)

				return testCEL, pcrValue
			},
			wantError: "found additional COS events after separator",
		},
		{
			name: "duplicate PIID",
			createCEL: func(t *testing.T) (eventLog []byte, pcrVal []byte) {
				pcrValue := make([]byte, 32)
				testCEL := createCELRecord(t, 0, hostcel.UserspacePCRIdx, &pcrValue, hostcel.CPUPIIDType, testPIID)
				// Duplicate PIID event should cause an error.
				testCEL = append(testCEL, createCELRecord(t, 1, hostcel.UserspacePCRIdx, &pcrValue, hostcel.CPUPIIDType, testPIID)...)
				testCEL = append(testCEL, createCELRecord(t, 2, hostcel.UserspacePCRIdx, &pcrValue, hostcel.LaunchSeparatorType, nil)...)

				return testCEL, pcrValue
			},
			wantError: "found duplicate CPUPIID event",
		},
		{
			name: "invalid PIID length",
			createCEL: func(t *testing.T) (eventLog []byte, pcrVal []byte) {
				pcrValue := make([]byte, 32)
				testCEL := createCELRecord(t, 0, hostcel.UserspacePCRIdx, &pcrValue, hostcel.CPUPIIDType, []byte{0x42})
				testCEL = append(testCEL, createCELRecord(t, 1, hostcel.UserspacePCRIdx, &pcrValue, hostcel.LaunchSeparatorType, nil)...)

				return testCEL, pcrValue
			},
			wantError: "invalid CPUPIID event length",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			testCEL, pcrValue := tc.createCEL(t)
			pcrBank := convertToPCRBank(t, &tpb.PCRs{
				Hash: tpb.HashAlgo_SHA256,
				Pcrs: map[uint32][]byte{
					hostcel.UserspacePCRIdx: pcrValue,
				},
			})

			_, err := parseCPUPIID(testCEL, pcrBank)
			if err == nil {
				t.Errorf("parseCPUPIID() succeeded, want error")
			} else if !strings.Contains(err.Error(), tc.wantError) {
				t.Errorf("parseCPUPIID() got error %v, want error %v", err, tc.wantError)
			}
		})
	}
}

func convertToPCRBank(t *testing.T, pcrs *tpb.PCRs) register.PCRBank {
	t.Helper()
	pcrBank := register.PCRBank{TCGHashAlgo: state.HashAlgo(pcrs.Hash)}
	digestAlg, err := pcrBank.TCGHashAlgo.CryptoHash()
	if err != nil {
		t.Fatal(err)
	}
	for ind, dgst := range pcrs.GetPcrs() {
		pcrBank.PCRs = append(pcrBank.PCRs, register.PCR{
			Index:     int(ind),
			Digest:    dgst,
			DigestAlg: digestAlg},
		)
	}
	return pcrBank
}

// createCELRecord builds a binary CEL record.
func createCELRecord(t *testing.T, recNum uint64, pcrIdx uint8, pcrValue *[]byte, eventType hostcel.ContentType, content []byte) []byte {
	// RecNum TLV.
	rnVal := make([]byte, 8)
	binary.BigEndian.PutUint64(rnVal, recNum)
	rnTLV := hostcel.COSTLV{EventType: 0, EventContent: rnVal}

	// Index TLV.
	idxTLV := hostcel.COSTLV{EventType: hostcel.ContentType(cel.PCRType), EventContent: []byte{pcrIdx}}

	// Content TLV (Nested COSTLV).
	marshalCOSTLV := func(tlv hostcel.COSTLV) []byte {
		t.Helper()
		buf := make([]byte, 5+len(tlv.EventContent))
		buf[0] = uint8(tlv.EventType)
		binary.BigEndian.PutUint32(buf[1:], uint32(len(tlv.EventContent)))
		copy(buf[5:], tlv.EventContent)
		return buf
	}

	innerTLV := hostcel.COSTLV{EventType: eventType, EventContent: content}
	contentTLV := hostcel.COSTLV{EventType: hostcel.ContentType(hostcel.CELRType), EventContent: marshalCOSTLV(innerTLV)}

	// Digest TLV
	h := sha256.Sum256(marshalCOSTLV(contentTLV))
	digestInnerTLV := hostcel.COSTLV{EventType: hostcel.ContentType(tpm2.TPMAlgSHA256), EventContent: h[:]}
	digestsTLV := hostcel.COSTLV{EventType: 3, EventContent: marshalCOSTLV(digestInnerTLV)}

	var record []byte
	record = append(record, marshalCOSTLV(rnTLV)...)
	record = append(record, marshalCOSTLV(idxTLV)...)
	record = append(record, marshalCOSTLV(digestsTLV)...)
	record = append(record, marshalCOSTLV(contentTLV)...)

	// Extend PCR value.
	hasher := sha256.New()
	hasher.Write(*pcrValue)
	hasher.Write(h[:])
	*pcrValue = hasher.Sum(nil)

	return record
}

// testHostAttestation is a HostAttestation object from a real machine.
func testHostAttestation(t *testing.T) *apb.HostAttestation {
	t.Helper()
	h := &apb.HostAttestation{}
	if err := proto.Unmarshal(titanQuoteDataProd, h); err != nil {
		t.Fatalf("failed to unmarshal host attestation: %v", err)
	}

	return h
}

func TestParseEKCertificate(t *testing.T) {
	ekc, err := parseEKCertificate(ekcDataDev)
	if err != nil {
		t.Fatalf("parseEKCertificate failed: %v", err)
	}

	// Verify a few fields to ensure parsing is correct.
	if ekc.Header.Header.SignatureVersion != 1 {
		t.Errorf("got SignatureVersion %v, want 1", ekc.Header.Header.SignatureVersion)
	}
	if ekc.Header.Header.KeyType != 8 { // KeyTypeTPMEK
		t.Errorf("got KeyType %v, want 8", ekc.Header.Header.KeyType)
	}
}

func TestValidateTitanEndorsement(t *testing.T) {
	endorsement := &apb.TpmAttestationEndorsement_TitanEndorsement{
		DiceCertChain: titanDiceChainDataDev,
		EkCert:        ekcDataDev,
	}

	titanValidationOpts := &titandice.ValidateScribeCertificateChainOptions{
		RwSigningKeyInfos:  []titandice.KeyInfo{rwSigningKeyInfoDev},
		ScribeCertificates: [][]byte{scribeCertDataDev, payloadKeyCertDataDev},
	}

	ekPub, err := validateTitanEndorsement(endorsement, titanValidationOpts)
	if err != nil {
		t.Fatalf("validateTitanEndorsement failed: %v", err)
	}

	if ekPub == nil {
		t.Errorf("validateTitanEndorsement returned nil ekPub")
	}
}

func TestTitanEndorsementProd(t *testing.T) {
	attestation := &apb.HostAttestation{}
	if err := proto.Unmarshal(titanQuoteDataProd, attestation); err != nil {
		t.Fatalf("failed to unmarshal attestation: %v", err)
	}

	opts := &VerifyOpts{
		HashAlgo: tpm2.TPMAlgSHA256,
		TitanValidationOpts: &titandice.ValidateScribeCertificateChainOptions{
			RwSigningKeyInfos:  []titandice.KeyInfo{rwSigningKeyInfoProd},
			ScribeCertificates: [][]byte{scribeCertDataProd, scribeCertData2Prod},
		},
	}

	_, err := validateTitanEndorsement(attestation.GetTpmQuote().GetEndorsement().GetTitanEndorsement(), opts.TitanValidationOpts)
	if err != nil {
		t.Fatalf("validateTitanEndorsement failed: %v", err)
	}
}

func TestVerifyAttestation(t *testing.T) {
	opts := &VerifyOpts{
		HashAlgo: tpm2.TPMAlgSHA256,
		TitanValidationOpts: &titandice.ValidateScribeCertificateChainOptions{
			RwSigningKeyInfos:  []titandice.KeyInfo{rwSigningKeyInfoProd},
			ScribeCertificates: [][]byte{scribeCertDataProd, scribeCertData2Prod},
		},
		Nonce: []byte{
			0x5d, 0x1b, 0x60, 0xcc, 0x2e, 0x01, 0x45, 0xa7, 0xc5, 0x94, 0xa5, 0x94, 0x04, 0x75, 0xa2, 0x29,
			0xd8, 0xb7, 0xe6, 0xda, 0x8d, 0xe6, 0xa4, 0x17, 0x56, 0x78, 0x36, 0xe8, 0x63, 0xff, 0xa6, 0x7a,
		},
	}

	// Expect error because event logs are dummy values.
	expectedError := "failed to parse and replay boot event log"

	_, err := VerifyAttestation(testHostAttestation(t), opts)
	if err == nil {
		t.Fatal("VerifyAttestation succeeded, want error")
	} else if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("VerifyAttestation() got error %v, want error %v", err, expectedError)
	}
}

func testValidGMESLog(t *testing.T) (rawLog []byte, pcrs *tpb.PCRs, expectedState *spb.GMESState) {
	separatorEvents := []tcg.Event{
		newSeparatorEvent(t, gmes.PCRConfig.BMCFirmwareIdx),
		newSeparatorEvent(t, gmes.PCRConfig.BIOSIdx),
		newSeparatorEvent(t, gmes.PCRConfig.HostKernelIdx),
	}

	bmcEvent := newEvent(t, gmes.PCRConfig.BMCFirmwareIdx, tcg.EFIHCRTMEvent, []byte(gmes.BMCData))
	biosEvent := newEvent(t, gmes.PCRConfig.BIOSIdx, tcg.GoogleDRTMEvent, []byte(gmes.BIOSData))
	kernelEvent := newEFIImageLoadEvent(t, gmes.PCRConfig.HostKernelIdx, 0x1000, 0x2000, 0x3000, []byte("test-dev-path"))

	validEvents := append([]tcg.Event{
		bmcEvent,
		biosEvent,
		kernelEvent,
	}, separatorEvents...)

	rawLog, pcrs = testEventLog(t, validEvents)
	expectedState = &spb.GMESState{
		BmcFirmwareDigest: bmcEvent.Digest,
		BiosDigest:        biosEvent.Digest,
		HostKernelDigest:  kernelEvent.Digest,
	}
	return rawLog, pcrs, expectedState
}

// newEvent creates a tcg.Event containing a GMES measurement.
func newEvent(t *testing.T, mrIndex uint32, eventType tcg.EventType, data []byte) tcg.Event {
	t.Helper()
	digest := sha256.Sum256(data)
	return tcg.Event{
		Index:  int(mrIndex),
		Type:   eventType,
		Data:   data,
		Digest: digest[:],
	}
}

// newSeparatorEvent creates a tcg.Separator event for the given MR index.
func newSeparatorEvent(t *testing.T, mrIndex uint32) tcg.Event {
	t.Helper()
	data := []byte{0, 0, 0, 0}
	digest := sha256.Sum256(data)
	return tcg.Event{
		Index:  int(mrIndex),
		Type:   tcg.Separator,
		Data:   data,
		Digest: digest[:],
	}
}

// newEFIImageLoadEvent creates a tcg.Event containing an EFI image load event.
func newEFIImageLoadEvent(t *testing.T, mrIndex uint32, loadAddr, length, linkAddr uint64, devPathData []byte) tcg.Event {
	t.Helper()
	header := tcg.EFIImageLoadHeader{
		LoadAddr:      loadAddr,
		Length:        length,
		LinkAddr:      linkAddr,
		DevicePathLen: uint64(len(devPathData)),
	}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	if _, err := buf.Write(devPathData); err != nil {
		t.Fatal(err)
	}
	return newEvent(t, mrIndex, tcg.EFIBootServicesApplication, buf.Bytes())
}

// testEventLog takes a slice of events and returns a slice of verified events
// by building a synthetic raw event log and replaying it.
func testEventLog(t *testing.T, events []tcg.Event) ([]byte, *tpb.PCRs) {
	t.Helper()

	buf := new(bytes.Buffer)
	// Spec ID event (SHA1 format)
	binary.Write(buf, binary.LittleEndian, uint32(0))    // PCRIndex
	binary.Write(buf, binary.LittleEndian, uint32(0x03)) // Type: NoAction
	binary.Write(buf, binary.LittleEndian, [20]byte{})   // Digest

	specIDBuf := new(bytes.Buffer)
	// "Spec ID Event03\0"
	binary.Write(specIDBuf, binary.LittleEndian, [16]byte{0x53, 0x70, 0x65, 0x63, 0x20, 0x49, 0x44, 0x20, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x30, 0x33, 0x00})
	binary.Write(specIDBuf, binary.LittleEndian, uint32(0))      // PlatformClass
	binary.Write(specIDBuf, binary.LittleEndian, uint8(0))       // VersionMinor
	binary.Write(specIDBuf, binary.LittleEndian, uint8(2))       // VersionMajor
	binary.Write(specIDBuf, binary.LittleEndian, uint8(0))       // Errata
	binary.Write(specIDBuf, binary.LittleEndian, uint8(8))       // UintnSize
	binary.Write(specIDBuf, binary.LittleEndian, uint32(1))      // NumAlgs
	binary.Write(specIDBuf, binary.LittleEndian, uint16(0x000B)) // SHA256 ID
	binary.Write(specIDBuf, binary.LittleEndian, uint16(32))     // SHA256 Size
	binary.Write(specIDBuf, binary.LittleEndian, uint8(0))       // VendorInfoSize

	specIDData := specIDBuf.Bytes()
	binary.Write(buf, binary.LittleEndian, uint32(len(specIDData)))
	buf.Write(specIDData)

	// Subsequent events (TPM 2.0 format)
	for _, e := range events {
		binary.Write(buf, binary.LittleEndian, uint32(e.Index))
		binary.Write(buf, binary.LittleEndian, uint32(e.Type))
		binary.Write(buf, binary.LittleEndian, uint32(1))      // NumDigests
		binary.Write(buf, binary.LittleEndian, uint16(0x000B)) // SHA256
		buf.Write(e.Digest)
		binary.Write(buf, binary.LittleEndian, uint32(len(e.Data)))
		buf.Write(e.Data)
	}

	rawLog := buf.Bytes()

	// Calculate PCRs for replay.
	pcrValues := make(map[int][]byte)
	for _, e := range events {
		h := sha256.New()
		if current, ok := pcrValues[e.Index]; ok {
			h.Write(current)
		} else {
			// First event for this PCR - initialize with zeros.
			// Note this is a simplification for some PCRs. PCRs 17-23 are initialized with 0xFF but
			// the DRTM event clears the index to 0x00 before extending. Starting with 0x00 is functionally
			// the same because DRTM is always the first event, but this is subtly different from the spec.
			initial := make([]byte, h.Size())
			if e.Type == tcg.EFIHCRTMEvent {
				initial[len(initial)-1] = 0x04
			}
			h.Write(initial)
		}
		h.Write(e.Digest)
		pcrValues[e.Index] = h.Sum(nil)
	}

	pcrMap := make(map[uint32][]byte)
	for idx, val := range pcrValues {
		pcrMap[uint32(idx)] = val[:]
	}

	return rawLog, &tpb.PCRs{
		Hash: tpb.HashAlgo_SHA256,
		Pcrs: pcrMap,
	}
}
