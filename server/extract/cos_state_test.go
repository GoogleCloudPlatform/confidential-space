package extract

import (
	"crypto"
	"testing"

	"github.com/google/confidential-space/server/coscel"
	"github.com/google/go-configfs-tsm/configfs/fakertmr"
	"github.com/google/go-eventlog/cel"
	"github.com/google/go-tdx-guest/rtmr"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
)

func TestVerifiedCosState(t *testing.T) {
	cos_event_log := &cel.CEL{}

	// add events
	testCELEvents := []struct {
		cosNestedEventType coscel.CosType
		register           int
		eventPayload       []byte
	}{
		{coscel.ImageRefType, coscel.CosRTMR, []byte("docker.io/bazel/experimental/test:latest")},
		{coscel.ImageDigestType, coscel.CosRTMR, []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")},
		{coscel.RestartPolicyType, coscel.CosRTMR, []byte(attestpb.RestartPolicy_Always.String())},
		{coscel.ImageIDType, coscel.CosRTMR, []byte("sha256:5DF4A1AC347DCF8CF5E9D0ABC04B04DB847D1B88D3B1CC1006F0ACB68E5A1F4B")},
		{coscel.EnvVarType, coscel.CosRTMR, []byte("foo=bar")},
		{coscel.EnvVarType, coscel.CosRTMR, []byte("bar=baz")},
		{coscel.EnvVarType, coscel.CosRTMR, []byte("baz=foo=bar")},
		{coscel.EnvVarType, coscel.CosRTMR, []byte("empty=")},
		{coscel.ArgType, coscel.CosRTMR, []byte("--x")},
		{coscel.ArgType, coscel.CosRTMR, []byte("--y")},
		{coscel.ArgType, coscel.CosRTMR, []byte("")},
		{coscel.MemoryMonitorType, coscel.CosRTMR, []byte{1}},
	}

	expectedEnvVars := make(map[string]string)
	expectedEnvVars["foo"] = "bar"
	expectedEnvVars["bar"] = "baz"
	expectedEnvVars["baz"] = "foo=bar"
	expectedEnvVars["empty"] = ""

	// wantContainerState := attestpb.ContainerState{
	// 	ImageReference: string(testCELEvents[0].eventPayload),
	// 	ImageDigest:    string(testCELEvents[1].eventPayload),
	// 	RestartPolicy:  attestpb.RestartPolicy_Always,
	// 	ImageId:        string(testCELEvents[3].eventPayload),
	// 	EnvVars:        expectedEnvVars,
	// 	Args:           []string{string(testCELEvents[8].eventPayload), string(testCELEvents[9].eventPayload), string(testCELEvents[10].eventPayload)},
	// }
	// enabled := true
	// wantHealthMonitoringState := attestpb.HealthMonitoringState{
	// 	MemoryEnabled: &enabled,
	// }

	fakeRTMR := fakertmr.CreateRtmrSubsystem(t.TempDir())

	for _, testEvent := range testCELEvents {
		cosEvent := coscel.CosTlv{EventType: testEvent.cosNestedEventType, EventContent: testEvent.eventPayload}

		err := cos_event_log.AppendEvent(cosEvent, []crypto.Hash{crypto.SHA384}, coscel.CosCCELMRIndex, func(_ crypto.Hash, ccmrIdx int, dgst []byte) error {
			return rtmr.ExtendDigestClient(fakeRTMR, ccmrIdx-1, dgst)
		})
		// err := cos_event_log.AppendEventRTMR(fakeRTMR, testEvent.register, cosEvent);
		if err != nil {
			t.Fatal(err)
		}
	}

	_, err := VerifiedCosState(*cos_event_log, cel.CCMRTypeValue)
	if err != nil {
		t.Error(err)
	}
}
