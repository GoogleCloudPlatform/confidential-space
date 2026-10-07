package extract

import (
	"bytes"
	"crypto"
	"io"
	"math/rand"
	"strings"
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

func testGpuReport(t *testing.T) (*attestpb.NvidiaAttestationReport, []byte) {
	t.Helper()
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
	return report, gpuEvidenceBytes
}

func TestVerifiedCosStateRTMR(t *testing.T) {
	cosEventLog := cel.NewConfComputeMR()

	report, gpuEvidenceBytes := testGpuReport(t)

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

	cosState, err := VerifiedCOSState(cosEventLog, uint8(cel.CCMRType), Options{PopulateGpuDeviceState: true})
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

	cosStateNoGpu, err := VerifiedCOSState(cosEventLog, uint8(cel.CCMRType), Options{})
	if err != nil {
		t.Errorf("VerifiedCOSState with empty options returned unexpected error: %v", err)
	}
	wantGpuDeviceStateNoGpu := attestationpb.GpuDeviceState{
		CcMode: attestationpb.GPUDeviceCCMode_ON,
	}
	if diff := cmp.Diff(cosStateNoGpu.GpuDeviceState, &wantGpuDeviceStateNoGpu, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected GPU device state diff with empty options: \n%v", diff)
	}
}

func TestVerifiedCosStateRTMRWithEmptyLog(t *testing.T) {
	cosEventLog := cel.NewConfComputeMR()
	cosState, err := VerifiedCOSState(cosEventLog, uint8(cel.CCMRType), Options{PopulateGpuDeviceState: true})
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

	cosStateNoGpu, err := VerifiedCOSState(cosEventLog, uint8(cel.CCMRType), Options{})
	if err != nil {
		t.Errorf("VerifiedCOSState() with empty log and empty options returned error %v, want nil", err)
	}
	if diff := cmp.Diff(cosStateNoGpu, wantCosState, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected cos state diff with empty options: \n%v", diff)
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

	acosState, err := ParseCOSCEL(buf.Bytes(), rtmrBank, Options{})
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

	report, gpuEvidenceBytes := testGpuReport(t)

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
	wantGpuDeviceState := attestationpb.GpuDeviceState{
		CcMode: attestationpb.GPUDeviceCCMode_ON,
	}
	wantGpuDeviceStateWithReport := attestationpb.GpuDeviceState{
		CcMode:                  attestationpb.GPUDeviceCCMode_ON,
		NvidiaAttestationReport: report,
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

	if acosState, err := ParseCOSCEL(buf.Bytes(), rtmrBank, Options{}); err != nil {
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

	if acosState, err := ParseCOSCEL(buf.Bytes(), rtmrBank, Options{PopulateGpuDeviceState: true}); err != nil {
		t.Errorf("expecting no error from ParseCOSCEL(), but get %v", err)
	} else {
		if diff := cmp.Diff(acosState.Container, &wantContainerState, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected container state difference:\n%v", diff)
		}
		if diff := cmp.Diff(acosState.HealthMonitoring, &wantHealthMonitoringState, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected health monitoring state difference:\n%v", diff)
		}
		if diff := cmp.Diff(acosState.GpuDeviceState, &wantGpuDeviceStateWithReport, protocmp.Transform()); diff != "" {
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
	if _, err = ParseCOSCEL(buf.Bytes(), hackedPCRBank, Options{}); err == nil {
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
		acosState, err := ParseCOSCEL(buf.Bytes(), pcrBank, Options{})
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

	report, gpuEvidenceBytes := testGpuReport(t)

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
		{coscel.GPUDeviceAttestationBindingType, coscel.EventPCRIndex, gpuEvidenceBytes},
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
	wantGpuDeviceStateWithReport := attestationpb.GpuDeviceState{
		CcMode:                  attestationpb.GPUDeviceCCMode_ON,
		NvidiaAttestationReport: report,
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

		if acosState, err := ParseCOSCEL(buf.Bytes(), pcrBank, Options{PopulateGpuDeviceState: false}); err != nil {
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

		if acosState, err := ParseCOSCEL(buf.Bytes(), pcrBank, Options{PopulateGpuDeviceState: true}); err != nil {
			t.Errorf("expecting no error from ParseCOSCEL(), but get %v", err)
		} else {
			if diff := cmp.Diff(acosState.Container, &wantContainerState, protocmp.Transform()); diff != "" {
				t.Errorf("unexpected container state difference:\n%v", diff)
			}
			if diff := cmp.Diff(acosState.HealthMonitoring, &wantHealthMonitoringState, protocmp.Transform()); diff != "" {
				t.Errorf("unexpected health monitoring state difference:\n%v", diff)
			}
			if diff := cmp.Diff(acosState.GpuDeviceState, &wantGpuDeviceStateWithReport, protocmp.Transform()); diff != "" {
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
		_, err := ParseCOSCEL(buf.Bytes(), pcrBank, Options{})
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

type fakeTEMSlot struct {
	index  int
	digest []byte
}

func (s fakeTEMSlot) Idx() int             { return s.index }
func (s fakeTEMSlot) Dgst() []byte         { return bytes.Clone(s.digest) }
func (s fakeTEMSlot) DgstAlg() crypto.Hash { return crypto.SHA384 }

type fakeTEMBank struct {
	mrType cel.MRType
	slots  map[int][]byte
}

func (b fakeTEMBank) CryptoHash() (crypto.Hash, error) { return crypto.SHA384, nil }
func (b fakeTEMBank) MRType() cel.MRType               { return b.mrType }
func (b fakeTEMBank) MRs() []register.MR {
	var mrs []register.MR
	for idx, dgst := range b.slots {
		mrs = append(mrs, fakeTEMSlot{index: idx, digest: dgst})
	}
	return mrs
}

type untypedBank struct{}

func (untypedBank) CryptoHash() (crypto.Hash, error) { return crypto.SHA384, nil }
func (untypedBank) MRs() []register.MR               { return nil }

func extendSHA384(cur, dgst []byte) []byte {
	h := crypto.SHA384.New()
	if len(cur) == 0 {
		cur = make([]byte, crypto.SHA384.Size())
	}
	h.Write(cur)
	h.Write(dgst)
	return h.Sum(nil)
}

func TestParsingTEMEventlog(t *testing.T) {
	acoscel := cel.NewConfComputeMR()
	var buf bytes.Buffer
	if err := acoscel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}

	bank := fakeTEMBank{
		mrType: cel.CCMRType,
		slots: map[int][]byte{
			coscel.EventTEMSlotIndex: make([]byte, crypto.SHA384.Size()),
		},
	}

	for _, b := range []register.MRBank{bank, &bank} {
		if _, err := ParseCOSCEL(buf.Bytes(), b, Options{}); err != nil {
			t.Errorf("ParseCOSCEL(empty, %T) = %v, want nil", b, err)
		}
	}

	report, gpuEvidenceBytes := testGpuReport(t)
	events := []struct {
		eventType coscel.ContentType
		payload   []byte
	}{
		{coscel.ImageRefType, []byte("docker.io/bazel/experimental/test:latest")},
		{coscel.ImageDigestType, []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")},
		{coscel.RestartPolicyType, []byte(attestationpb.RestartPolicy_Always.String())},
		{coscel.ImageIDType, []byte("sha256:5DF4A1AC347DCF8CF5E9D0ABC04B04DB847D1B88D3B1CC1006F0ACB68E5A1F4B")},
		{coscel.EnvVarType, []byte("foo=bar")},
		{coscel.ArgType, []byte("--x")},
		{coscel.MemoryMonitorType, []byte{1}},
		{coscel.GpuCCModeType, []byte(attestationpb.GPUDeviceCCMode_ON.String())},
		{coscel.GPUDeviceAttestationBindingType, gpuEvidenceBytes},
		{coscel.LaunchSeparatorType, nil},
	}

	slot2 := make([]byte, crypto.SHA384.Size())
	for _, ev := range events {
		cosEvent := coscel.COSTLV{EventType: ev.eventType, EventContent: ev.payload}
		err := acoscel.AppendEvent(cosEvent, []crypto.Hash{crypto.SHA384}, coscel.EventTEMSlotIndex, func(_ crypto.Hash, mrIndex int, dgst []byte) error {
			if mrIndex == coscel.EventTEMSlotIndex {
				slot2 = extendSHA384(slot2, dgst)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	buf.Reset()
	if err := acoscel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	bank.slots[coscel.EventTEMSlotIndex] = slot2

	enabled := true
	wantState := &attestationpb.AttestedCosState{
		Container: &attestationpb.ContainerState{
			ImageReference: "docker.io/bazel/experimental/test:latest",
			ImageDigest:    "sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483",
			RestartPolicy:  attestationpb.RestartPolicy_Always,
			ImageId:        "sha256:5DF4A1AC347DCF8CF5E9D0ABC04B04DB847D1B88D3B1CC1006F0ACB68E5A1F4B",
			EnvVars:        map[string]string{"foo": "bar"},
			Args:           []string{"--x"},
		},
		HealthMonitoring: &attestationpb.HealthMonitoringState{
			MemoryEnabled: &enabled,
		},
		GpuDeviceState: &attestationpb.GpuDeviceState{
			CcMode:                  attestationpb.GPUDeviceCCMode_ON,
			NvidiaAttestationReport: report,
		},
	}

	gotState, err := ParseCOSCEL(buf.Bytes(), &bank, Options{PopulateGpuDeviceState: true})
	if err != nil {
		t.Fatalf("ParseCOSCEL(TEM slot 2) = %v, want nil", err)
	}
	if diff := cmp.Diff(gotState, wantState, protocmp.Transform()); diff != "" {
		t.Errorf("ParseCOSCEL(TEM slot 2) diff (-got +want):\n%s", diff)
	}
}

func TestParseCOSCELErrors(t *testing.T) {
	buildCCMRLog := func(t *testing.T, indices ...int) ([]byte, map[int][]byte) {
		t.Helper()
		log := cel.NewConfComputeMR()
		slots := map[int][]byte{}
		for _, idx := range indices {
			ev := coscel.COSTLV{EventType: coscel.ArgType, EventContent: []byte("--arg")}
			err := log.AppendEvent(ev, []crypto.Hash{crypto.SHA384}, idx, func(_ crypto.Hash, mrIndex int, dgst []byte) error {
				slots[mrIndex] = extendSHA384(slots[mrIndex], dgst)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		var b bytes.Buffer
		if err := log.EncodeCEL(&b); err != nil {
			t.Fatal(err)
		}
		return b.Bytes(), slots
	}

	emptyLog, _ := buildCCMRLog(t)
	idx2Log, idx2Slots := buildCCMRLog(t, coscel.EventTEMSlotIndex)
	idx4Log, idx4Slots := buildCCMRLog(t, coscel.COSCCELMRIndex)
	badIdxLog, badIdxSlots := buildCCMRLog(t, 3)
	mixed42Log, mixed42Slots := buildCCMRLog(t, coscel.COSCCELMRIndex, coscel.EventTEMSlotIndex)
	mixed24Log, mixed24Slots := buildCCMRLog(t, coscel.EventTEMSlotIndex, coscel.COSCCELMRIndex)

	tests := []struct {
		name    string
		log     []byte
		bank    register.MRBank
		wantErr string
	}{
		{
			name:    "unknown_mr_type_from_typed_bank",
			log:     emptyLog,
			bank:    fakeTEMBank{mrType: cel.MRType(99)},
			wantErr: "unknown CEL MRType 99",
		},
		{
			name:    "untyped_custom_bank",
			log:     idx2Log,
			bank:    untypedBank{},
			wantErr: "unknown register type",
		},
		{
			name:    "unexpected_ccmr_index_3",
			log:     badIdxLog,
			bank:    fakeTEMBank{mrType: cel.CCMRType, slots: badIdxSlots},
			wantErr: "found unexpected CCELMR 3",
		},
		{
			name: "rtmr_bank_with_tem_index_2",
			log:  idx2Log,
			bank: register.RTMRBank{
				RTMRs: []register.RTMR{
					{Index: coscel.EventTEMSlotIndex - 1, Digest: idx2Slots[coscel.EventTEMSlotIndex]},
				},
			},
			wantErr: "found unexpected CCELMR 2",
		},
		{
			name:    "tem_bank_with_rtmr_index_4",
			log:     idx4Log,
			bank:    fakeTEMBank{mrType: cel.CCMRType, slots: idx4Slots},
			wantErr: "found unexpected CCELMR 4",
		},
		{
			name:    "mixed_ccmr_indices_4_then_2",
			log:     mixed42Log,
			bank:    fakeTEMBank{mrType: cel.CCMRType, slots: mixed42Slots},
			wantErr: "found unexpected CCELMR 4",
		},
		{
			name:    "mixed_ccmr_indices_2_then_4",
			log:     mixed24Log,
			bank:    fakeTEMBank{mrType: cel.CCMRType, slots: mixed24Slots},
			wantErr: "found unexpected CCELMR 4",
		},
		{
			name: "tem_slot2_replay_mismatch",
			log:  idx2Log,
			bank: fakeTEMBank{
				mrType: cel.CCMRType,
				slots:  map[int][]byte{coscel.EventTEMSlotIndex: make([]byte, crypto.SHA384.Size())},
			},
			wantErr: "CEL replay failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseCOSCEL(tc.log, tc.bank, Options{}); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("ParseCOSCEL(%s, %T) = %v, want error containing %q", tc.name, tc.bank, err, tc.wantErr)
			}
		})
	}
}
