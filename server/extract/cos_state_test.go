package extract

import (
	"bytes"
	"crypto"
	"io"
	"math/rand"
	"testing"

	"github.com/GoogleCloudPlatform/confidential-space/server/coscel"
	attestpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-configfs-tsm/configfs/fakertmr"
	configfstsmrtmr "github.com/google/go-configfs-tsm/rtmr"
	"github.com/google/go-eventlog/cel"
	"github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-tdx-guest/rtmr"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/google/go-tpm-tools/client"
	attestationpb "github.com/google/go-tpm-tools/proto/attest"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/simulator"
)

func TestVerifiedCosStateRTMR(t *testing.T) {
	cosEventLog := cel.NewConfComputeMR()

	report := &attestpb.NvidiaAttestationReport{
		CcFeature: &attestpb.NvidiaAttestationReport_Spt{
			Spt: &attestpb.NvidiaAttestationReport_SinglePassthroughAttestation{
				GpuQuote: &attestpb.GpuInfo{
					Uuid:                "fake-gpu-uuid",
					VbiosVersion:        "fake-vbios-version",
					DriverVersion:       "fake-driver-version",
					GpuArchitectureType: attestpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_BLACKWELL,
				},
			},
		},
	}
	gpuEvidenceBytes, err := proto.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal mock GPU evidence: %v", err)
	}

	wantGpuDeviceState := attestationpb.GpuDeviceState{
		CcMode:                  attestationpb.GPUDeviceCCMode_ON,
		NvidiaAttestationReport: report,
	}

	// add events
	testCELEvents := []struct {
		cosNestedEventType coscel.ContentType
		register           int
		eventPayload       []byte
	}{
		{coscel.ImageRefType, coscel.EventRTMRIndex, []byte("docker.io/bazel/experimental/test:latest")},
		{coscel.ImageDigestType, coscel.EventRTMRIndex, []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")},
		{coscel.RestartPolicyType, coscel.EventRTMRIndex, []byte(attestationpb.RestartPolicy_Always.String())},
		{coscel.ImageIDType, coscel.EventRTMRIndex, []byte("sha256:5DF4A1AC347DCF8CF5E9D0ABC04B04DB847D1B88D3B1CC1006F0ACB68E5A1F4B")},
		{coscel.EnvVarType, coscel.EventRTMRIndex, []byte("foo=bar")},
		{coscel.EnvVarType, coscel.EventRTMRIndex, []byte("bar=baz")},
		{coscel.EnvVarType, coscel.EventRTMRIndex, []byte("baz=foo=bar")},
		{coscel.EnvVarType, coscel.EventRTMRIndex, []byte("empty=")},
		{coscel.ArgType, coscel.EventRTMRIndex, []byte("--x")},
		{coscel.ArgType, coscel.EventRTMRIndex, []byte("--y")},
		{coscel.ArgType, coscel.EventRTMRIndex, []byte("")},
		{coscel.MemoryMonitorType, coscel.EventRTMRIndex, []byte{1}},
		{coscel.GpuCCModeType, coscel.EventRTMRIndex, []byte(attestationpb.GPUDeviceCCMode_ON.String())},
		{coscel.GPUDeviceAttestationBindingType, coscel.EventRTMRIndex, gpuEvidenceBytes},
	}

	expectedEnvVars := make(map[string]string)
	expectedEnvVars["foo"] = "bar"
	expectedEnvVars["bar"] = "baz"
	expectedEnvVars["baz"] = "foo=bar"
	expectedEnvVars["empty"] = ""

	wantContainerState := attestationpb.ContainerState{
		ImageReference: string(testCELEvents[0].eventPayload),
		ImageDigest:    string(testCELEvents[1].eventPayload),
		RestartPolicy:  attestationpb.RestartPolicy_Always,
		ImageId:        string(testCELEvents[3].eventPayload),
		EnvVars:        expectedEnvVars,
		Args:           []string{string(testCELEvents[8].eventPayload), string(testCELEvents[9].eventPayload), string(testCELEvents[10].eventPayload)},
	}
	enabled := true
	wantHealthMonitoringState := attestationpb.HealthMonitoringState{
		MemoryEnabled: &enabled,
	}

	fakeRTMR := fakertmr.CreateRtmrSubsystem(t.TempDir())

	for _, testEvent := range testCELEvents {
		cosEvent := coscel.COSTLV{EventType: testEvent.cosNestedEventType, EventContent: testEvent.eventPayload}

		err := cosEventLog.AppendEvent(cosEvent, []crypto.Hash{crypto.SHA384}, coscel.COSCCELMRIndex, func(_ crypto.Hash, ccmrIdx int, dgst []byte) error {
			return rtmr.ExtendDigestClient(fakeRTMR, ccmrIdx-1, dgst)
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	cosState, err := VerifiedCOSState(cosEventLog, uint8(cel.CCMRType))
	if err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(cosState.Container, &wantContainerState, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected container state diff: \n%v", diff)
	}

	if diff := cmp.Diff(cosState.HealthMonitoring, &wantHealthMonitoringState, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected health monitoring state diff: \n%v", diff)
	}

	if diff := cmp.Diff(cosState.GpuDeviceState, &wantGpuDeviceState, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected GPU device state diff: \n%v", diff)
	}

}

func TestVerifiedCosStateRTMRWithEmptyLog(t *testing.T) {
	cosEventLog := cel.NewConfComputeMR()
	cosState, err := VerifiedCOSState(cosEventLog, uint8(cel.CCMRType))
	if err != nil {
		t.Errorf("VerifiedCOSState() with empty log returned error %v, want nil", err)
	}

	wantCosState := &attestationpb.AttestedCosState{
		Container: &attestationpb.ContainerState{
			Args:              []string{},
			EnvVars:           map[string]string{},
			OverriddenEnvVars: map[string]string{},
		},
		HealthMonitoring: &attestationpb.HealthMonitoringState{},
		GpuDeviceState:   &attestationpb.GpuDeviceState{},
	}

	if diff := cmp.Diff(cosState, wantCosState, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected cos state diff: \n%v", diff)
	}
}

func convertToPCRBank(t *testing.T, pcrs *pb.PCRs) register.PCRBank {
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

func getRTMRBank(t *testing.T, fakeRTMR *fakertmr.RtmrSubsystem) register.RTMRBank {
	rtmrBank := register.RTMRBank{}
	// RTMR 0 to 3
	for i := 0; i < 4; i++ {
		digest, err := configfstsmrtmr.GetDigest(fakeRTMR, i)
		if err != nil {
			t.Fatal(err)
		}
		rtmrBank.RTMRs = append(rtmrBank.RTMRs, register.RTMR{Index: i, Digest: digest.Digest})
	}
	return rtmrBank
}

func TestParsingRTMREventlog(t *testing.T) {
	acoscel := cel.NewConfComputeMR()
	emptyCosState := attestationpb.ContainerState{}
	emptyHealthMonitoringState := attestationpb.HealthMonitoringState{}
	emptyGpuDeviceState := attestationpb.GpuDeviceState{}

	var buf bytes.Buffer
	// First, encode an empty CEL and try to parse it.
	if err := acoscel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}

	fakeRTMR := fakertmr.CreateRtmrSubsystem(t.TempDir())
	rtmrBank := getRTMRBank(t, fakeRTMR)

	acosState, err := ParseCOSCEL(buf.Bytes(), rtmrBank)
	if err != nil {
		t.Fatalf("expecting no error from ParseCOSCEL(), but get %v", err)
	}
	if diff := cmp.Diff(acosState.Container, &emptyCosState, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected container state difference:\n%v", diff)
	}
	if diff := cmp.Diff(acosState.HealthMonitoring, &emptyHealthMonitoringState, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected health monitoring difference:\n%v", diff)
	}
	if acosState.HealthMonitoring.MemoryEnabled != nil {
		t.Errorf("unexpected MemoryEnabled state, want nil, but got %v", *acosState.HealthMonitoring.MemoryEnabled)
	}
	if diff := cmp.Diff(acosState.GpuDeviceState, &emptyGpuDeviceState, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected GPU device state difference:\n%v", diff)
	}

	// add events
	testCELEvents := []struct {
		cosNestedEventType coscel.ContentType
		register           int
		eventPayload       []byte
	}{
		{coscel.ImageRefType, coscel.EventRTMRIndex, []byte("docker.io/bazel/experimental/test:latest")},
		{coscel.ImageDigestType, coscel.EventRTMRIndex, []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")},
		{coscel.RestartPolicyType, coscel.EventRTMRIndex, []byte(attestationpb.RestartPolicy_Always.String())},
		{coscel.ImageIDType, coscel.EventRTMRIndex, []byte("sha256:5DF4A1AC347DCF8CF5E9D0ABC04B04DB847D1B88D3B1CC1006F0ACB68E5A1F4B")},
		{coscel.EnvVarType, coscel.EventRTMRIndex, []byte("foo=bar")},
		{coscel.EnvVarType, coscel.EventRTMRIndex, []byte("bar=baz")},
		{coscel.EnvVarType, coscel.EventRTMRIndex, []byte("baz=foo=bar")},
		{coscel.EnvVarType, coscel.EventRTMRIndex, []byte("empty=")},
		{coscel.ArgType, coscel.EventRTMRIndex, []byte("--x")},
		{coscel.ArgType, coscel.EventRTMRIndex, []byte("--y")},
		{coscel.ArgType, coscel.EventRTMRIndex, []byte("")},
		{coscel.MemoryMonitorType, coscel.EventRTMRIndex, []byte{1}},
		{coscel.GpuCCModeType, coscel.EventRTMRIndex, []byte(attestationpb.GPUDeviceCCMode_ON.String())},
	}

	expectedEnvVars := make(map[string]string)
	expectedEnvVars["foo"] = "bar"
	expectedEnvVars["bar"] = "baz"
	expectedEnvVars["baz"] = "foo=bar"
	expectedEnvVars["empty"] = ""

	wantContainerState := attestationpb.ContainerState{
		ImageReference: string(testCELEvents[0].eventPayload),
		ImageDigest:    string(testCELEvents[1].eventPayload),
		RestartPolicy:  attestationpb.RestartPolicy_Always,
		ImageId:        string(testCELEvents[3].eventPayload),
		EnvVars:        expectedEnvVars,
		Args:           []string{string(testCELEvents[8].eventPayload), string(testCELEvents[9].eventPayload), string(testCELEvents[10].eventPayload)},
	}
	enabled := true
	wantHealthMonitoringState := attestationpb.HealthMonitoringState{
		MemoryEnabled: &enabled,
	}
	wantGpuDeviceState := attestationpb.GpuDeviceState{
		CcMode: attestationpb.GPUDeviceCCMode_ON,
	}

	for _, testEvent := range testCELEvents {
		cosEvent := coscel.COSTLV{EventType: testEvent.cosNestedEventType, EventContent: testEvent.eventPayload}
		if err := acoscel.AppendEvent(cosEvent, []crypto.Hash{crypto.SHA384}, coscel.COSCCELMRIndex, func(_ crypto.Hash, mrIndex int, digest []byte) error {
			return rtmr.ExtendDigestClient(fakeRTMR, mrIndex-1, digest) // MR_INDEX - 1 == RTMR_INDEX
		}); err != nil {
			t.Fatal(err)
		}
	}
	buf = bytes.Buffer{}
	if err := acoscel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}

	rtmrBank = getRTMRBank(t, fakeRTMR)

	if acosState, err := ParseCOSCEL(buf.Bytes(), rtmrBank); err != nil {
		t.Errorf("expecting no error from ParseCOSCEL(), but get %v", err)
	} else {
		if diff := cmp.Diff(acosState.Container, &wantContainerState, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected container state difference:\n%v", diff)
		}
		if diff := cmp.Diff(acosState.HealthMonitoring, &wantHealthMonitoringState, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected health monitoring state difference:\n%v", diff)
		}
		if diff := cmp.Diff(acosState.GpuDeviceState, &wantGpuDeviceState, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected GPU device state difference:\n%v", diff)
		}
	}

	// Faking PCR with RTMR should fail
	imposterPcrBank := map[uint32][]byte{}
	imposterPcrBank[1] = rtmrBank.RTMRs[0].Digest
	imposterPcrBank[2] = rtmrBank.RTMRs[1].Digest
	imposterPcrBank[3] = rtmrBank.RTMRs[2].Digest
	imposterPcrBank[4] = rtmrBank.RTMRs[3].Digest
	imposterPcrs := &pb.PCRs{Hash: pb.HashAlgo_SHA384, Pcrs: imposterPcrBank}
	hackedPCRBank := convertToPCRBank(t, imposterPcrs)
	if _, err = ParseCOSCEL(buf.Bytes(), hackedPCRBank); err == nil {
		t.Errorf("expecting error from ParseCOSCEL() when using RTMR CEL Log, but get nil")
	}
}

func TestParsingCELEventLog(t *testing.T) {
	tpm, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer client.CheckedClose(t, tpm)

	acoscel := cel.NewPCR()
	emptyCosState := attestationpb.ContainerState{}
	emptyHealthMonitoringState := attestationpb.HealthMonitoringState{}
	emptyGpuDeviceState := attestationpb.GpuDeviceState{}

	var buf bytes.Buffer
	// First, encode an empty CEL and try to parse it.
	if err := acoscel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	banks, err := client.ReadAllPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}

	for _, bank := range banks {
		pcrBank := convertToPCRBank(t, bank)
		// pcrs can have any value here, since the cel has no records, the replay should always success.
		acosState, err := ParseCOSCEL(buf.Bytes(), pcrBank)
		if err != nil {
			t.Fatalf("expecting no error from ParseCOSCEL(), but get %v", err)
		}
		if diff := cmp.Diff(acosState.Container, &emptyCosState, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected container state difference:\n%v", diff)
		}
		if diff := cmp.Diff(acosState.HealthMonitoring, &emptyHealthMonitoringState, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected health monitoring difference:\n%v", diff)
		}
		if acosState.HealthMonitoring.MemoryEnabled != nil {
			t.Errorf("unexpected MemoryEnabled state, want nil, but got %v", *acosState.HealthMonitoring.MemoryEnabled)
		}
		if diff := cmp.Diff(acosState.GpuDeviceState, &emptyGpuDeviceState, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected GPU device state difference:\n%v", diff)
		}
	}

	// Secondly, append some real COS events to the CEL. This time we should get content in the CosState.
	testCELEvents := []struct {
		cosNestedEventType coscel.ContentType
		pcr                int
		eventPayload       []byte
	}{
		{coscel.ImageRefType, coscel.EventPCRIndex, []byte("docker.io/bazel/experimental/test:latest")},
		{coscel.ImageDigestType, coscel.EventPCRIndex, []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")},
		{coscel.RestartPolicyType, coscel.EventPCRIndex, []byte(attestationpb.RestartPolicy_Always.String())},
		{coscel.ImageIDType, coscel.EventPCRIndex, []byte("sha256:5DF4A1AC347DCF8CF5E9D0ABC04B04DB847D1B88D3B1CC1006F0ACB68E5A1F4B")},
		{coscel.EnvVarType, coscel.EventPCRIndex, []byte("foo=bar")},
		{coscel.EnvVarType, coscel.EventPCRIndex, []byte("bar=baz")},
		{coscel.EnvVarType, coscel.EventPCRIndex, []byte("baz=foo=bar")},
		{coscel.EnvVarType, coscel.EventPCRIndex, []byte("empty=")},
		{coscel.ArgType, coscel.EventPCRIndex, []byte("--x")},
		{coscel.ArgType, coscel.EventPCRIndex, []byte("--y")},
		{coscel.ArgType, coscel.EventPCRIndex, []byte("")},
		{coscel.MemoryMonitorType, coscel.EventPCRIndex, []byte{1}},
		{coscel.GpuCCModeType, coscel.EventPCRIndex, []byte(attestationpb.GPUDeviceCCMode_ON.String())},
	}

	expectedEnvVars := make(map[string]string)
	expectedEnvVars["foo"] = "bar"
	expectedEnvVars["bar"] = "baz"
	expectedEnvVars["baz"] = "foo=bar"
	expectedEnvVars["empty"] = ""

	wantContainerState := attestationpb.ContainerState{
		ImageReference: string(testCELEvents[0].eventPayload),
		ImageDigest:    string(testCELEvents[1].eventPayload),
		RestartPolicy:  attestationpb.RestartPolicy_Always,
		ImageId:        string(testCELEvents[3].eventPayload),
		EnvVars:        expectedEnvVars,
		Args:           []string{string(testCELEvents[8].eventPayload), string(testCELEvents[9].eventPayload), string(testCELEvents[10].eventPayload)},
	}
	enabled := true
	wantHealthMonitoringState := attestationpb.HealthMonitoringState{
		MemoryEnabled: &enabled,
	}
	wantGpuDeviceState := attestationpb.GpuDeviceState{
		CcMode: attestationpb.GPUDeviceCCMode_ON,
	}
	banks, err = client.ReadAllPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	implementedHashes := getImplementedHashes(t, banks)
	for _, testEvent := range testCELEvents {
		cosEvent := coscel.COSTLV{EventType: testEvent.cosNestedEventType, EventContent: testEvent.eventPayload}

		if err := acoscel.AppendEvent(cosEvent, implementedHashes, testEvent.pcr, pcrExtender(tpm)); err != nil {
			t.Fatal(err)
		}
	}
	buf = bytes.Buffer{}
	if err := acoscel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	banks, err = client.ReadAllPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	for _, bank := range banks {
		pcrBank := convertToPCRBank(t, bank)

		if acosState, err := ParseCOSCEL(buf.Bytes(), pcrBank); err != nil {
			t.Errorf("expecting no error from ParseCOSCEL(), but get %v", err)
		} else {
			if diff := cmp.Diff(acosState.Container, &wantContainerState, protocmp.Transform()); diff != "" {
				t.Errorf("unexpected container state difference:\n%v", diff)
			}
			if diff := cmp.Diff(acosState.HealthMonitoring, &wantHealthMonitoringState, protocmp.Transform()); diff != "" {
				t.Errorf("unexpected health monitoring state difference:\n%v", diff)
			}
			if diff := cmp.Diff(acosState.GpuDeviceState, &wantGpuDeviceState, protocmp.Transform()); diff != "" {
				t.Errorf("unexpected GPU device state difference:\n%v", diff)
			}
		}
	}

	// Thirdly, append a random non-COS event, encode and try to parse it.
	// Because there is no COS TLV event, attestation should fail as we do not
	// understand the content type.
	event, err := generateNonCOSCELEvent(implementedHashes)
	if err != nil {
		t.Fatal(err)
	}
	acoscel.AppendEvent(event, implementedHashes, coscel.EventPCRIndex, pcrExtender(tpm))
	buf = bytes.Buffer{}
	if err := acoscel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	banks, err = client.ReadAllPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	for _, bank := range banks {
		pcrBank := convertToPCRBank(t, bank)
		_, err := ParseCOSCEL(buf.Bytes(), pcrBank)
		if err == nil {
			t.Errorf("expected error when parsing event log with unknown content type")
		}
	}
}

type otherTLV struct {
	tlv cel.TLV
}

func (o otherTLV) TLV() (cel.TLV, error) {
	return o.tlv, nil
}

func (o otherTLV) GenerateDigest(hashAlgo crypto.Hash) ([]byte, error) {
	contentTLV, err := o.TLV()
	if err != nil {
		return nil, err
	}

	b, err := contentTLV.MarshalBinary()
	if err != nil {
		return nil, err
	}

	hash := hashAlgo.New()
	if _, err = hash.Write(b); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func generateNonCOSCELEvent(hashAlgoList []crypto.Hash) (cel.Content, error) {
	contentValue := make([]byte, 10)
	rand.Read(contentValue)
	tlv := cel.TLV{Type: 250, Value: contentValue}
	return otherTLV{tlv: tlv}, nil
}

func getImplementedHashes(t *testing.T, banks []*pb.PCRs) []crypto.Hash {
	t.Helper()
	var implementedHashes []crypto.Hash
	// Get all implemented hash algos in the TPM.
	for _, h := range banks {
		hsh, err := tpm2.Algorithm(h.Hash).Hash()
		if err != nil {
			t.Fatal(err)
		}
		implementedHashes = append(implementedHashes, crypto.Hash(hsh))
	}
	return implementedHashes
}

func pcrExtender(tpm io.ReadWriter) cel.MRExtender {
	return func(hash crypto.Hash, mrIndex int, digest []byte) error {
		return extendDigestToPCR(tpm, hash, mrIndex, digest)
	}
}

func extendDigestToPCR(tpm io.ReadWriter, algo crypto.Hash, mrIndex int, digest []byte) error {
	tpm2Algo, err := tpm2.HashToAlgorithm(algo)
	if err != nil {
		return err
	}
	return tpm2.PCRExtend(tpm, tpmutil.Handle(mrIndex), tpm2Algo, digest, "")
}
