package extract

import (
	"crypto"
	"testing"

	"github.com/GoogleCloudPlatform/confidential-space/server/coscel"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-configfs-tsm/configfs/fakertmr"
	"github.com/google/go-eventlog/cel"
	"github.com/google/go-tdx-guest/rtmr"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestVerifiedCosStateRTMR(t *testing.T) {
	cosEventLog := cel.NewConfComputeMR()

	// add events
	testCELEvents := []struct {
		cosNestedEventType coscel.ContentType
		register           int
		eventPayload       []byte
	}{
		{coscel.ImageRefType, coscel.EventRTMRIndex, []byte("docker.io/bazel/experimental/test:latest")},
		{coscel.ImageDigestType, coscel.EventRTMRIndex, []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")},
		{coscel.RestartPolicyType, coscel.EventRTMRIndex, []byte(attestpb.RestartPolicy_Always.String())},
		{coscel.ImageIDType, coscel.EventRTMRIndex, []byte("sha256:5DF4A1AC347DCF8CF5E9D0ABC04B04DB847D1B88D3B1CC1006F0ACB68E5A1F4B")},
		{coscel.EnvVarType, coscel.EventRTMRIndex, []byte("foo=bar")},
		{coscel.EnvVarType, coscel.EventRTMRIndex, []byte("bar=baz")},
		{coscel.EnvVarType, coscel.EventRTMRIndex, []byte("baz=foo=bar")},
		{coscel.EnvVarType, coscel.EventRTMRIndex, []byte("empty=")},
		{coscel.ArgType, coscel.EventRTMRIndex, []byte("--x")},
		{coscel.ArgType, coscel.EventRTMRIndex, []byte("--y")},
		{coscel.ArgType, coscel.EventRTMRIndex, []byte("")},
		{coscel.MemoryMonitorType, coscel.EventRTMRIndex, []byte{1}},
	}

	expectedEnvVars := make(map[string]string)
	expectedEnvVars["foo"] = "bar"
	expectedEnvVars["bar"] = "baz"
	expectedEnvVars["baz"] = "foo=bar"
	expectedEnvVars["empty"] = ""

	wantContainerState := attestpb.ContainerState{
		ImageReference: string(testCELEvents[0].eventPayload),
		ImageDigest:    string(testCELEvents[1].eventPayload),
		RestartPolicy:  attestpb.RestartPolicy_Always,
		ImageId:        string(testCELEvents[3].eventPayload),
		EnvVars:        expectedEnvVars,
		Args:           []string{string(testCELEvents[8].eventPayload), string(testCELEvents[9].eventPayload), string(testCELEvents[10].eventPayload)},
	}
	enabled := true
	wantHealthMonitoringState := attestpb.HealthMonitoringState{
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
}
