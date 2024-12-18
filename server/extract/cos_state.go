package extract

import (
	"fmt"

	"github.com/GoogleCloudPlatform/confidential-space/server/coscel"
	"github.com/google/go-eventlog/cel"
	pb "github.com/google/go-tpm-tools/proto/attest"
)

func VerifiedCosState(event_log cel.CEL, registerType uint8) (*pb.AttestedCosState, error) {
	cosState := &pb.AttestedCosState{}
	cosState.Container = &pb.ContainerState{}
	cosState.HealthMonitoring = &pb.HealthMonitoringState{}
	cosState.Container.Args = make([]string, 0)
	cosState.Container.EnvVars = make(map[string]string)
	cosState.Container.OverriddenEnvVars = make(map[string]string)

	seenSeparator := false
	for _, record := range event_log.Records() {
		if record.IndexType != registerType {
			return nil, fmt.Errorf("expect registerType: %d, but get %d in a CEL record", registerType, record.IndexType)
		}

		switch record.IndexType {
		case uint8(cel.PCRType):
			if record.Index != coscel.CosEventPCR {
				return nil, fmt.Errorf("found unexpected PCR %d in COS CEL log", record.Index)
			}
		case uint8(cel.CCMRType):
			if record.Index != coscel.CosCCELMRIndex {
				return nil, fmt.Errorf("found unexpected CCELMR %d in COS CEL log", record.Index)
			}
		default:
			return nil, fmt.Errorf("unknown COS CEL log index type %d", record.IndexType)
		}

		// The Content.Type is not verified at this point, so we have to fail
		// if we see any events that we do not understand. This ensures that
		// we either verify the digest of event event in this PCR, or we fail
		// to replay the event log.
		// TODO: See if we can fix this to have the Content Type be verified.
		cosTlv, err := coscel.ParseToCosTlv(record.Content)
		if err != nil {
			return nil, err
		}

		// verify digests for the cos cel content
		if err := cel.VerifyDigests(cosTlv, record.Digests); err != nil {
			return nil, err
		}

		// TODO: Add support for post-separator container data
		if seenSeparator {
			return nil, fmt.Errorf("found COS Event Type %v after LaunchSeparator event", cosTlv.EventType)
		}

		switch cosTlv.EventType {
		case coscel.ImageRefType:
			if cosState.Container.GetImageReference() != "" {
				return nil, fmt.Errorf("found more than one ImageRef event")
			}
			cosState.Container.ImageReference = string(cosTlv.EventContent)

		case coscel.ImageDigestType:
			if cosState.Container.GetImageDigest() != "" {
				return nil, fmt.Errorf("found more than one ImageDigest event")
			}
			cosState.Container.ImageDigest = string(cosTlv.EventContent)

		case coscel.RestartPolicyType:
			restartPolicy, ok := pb.RestartPolicy_value[string(cosTlv.EventContent)]
			if !ok {
				return nil, fmt.Errorf("unknown restart policy in COS eventlog: %s", string(cosTlv.EventContent))
			}
			cosState.Container.RestartPolicy = pb.RestartPolicy(restartPolicy)

		case coscel.ImageIDType:
			if cosState.Container.GetImageId() != "" {
				return nil, fmt.Errorf("found more than one ImageId event")
			}
			cosState.Container.ImageId = string(cosTlv.EventContent)

		case coscel.EnvVarType:
			envName, envVal, err := coscel.ParseEnvVar(string(cosTlv.EventContent))
			if err != nil {
				return nil, err
			}
			cosState.Container.EnvVars[envName] = envVal

		case coscel.ArgType:
			cosState.Container.Args = append(cosState.Container.Args, string(cosTlv.EventContent))

		case coscel.OverrideArgType:
			cosState.Container.OverriddenArgs = append(cosState.Container.OverriddenArgs, string(cosTlv.EventContent))

		case coscel.OverrideEnvType:
			envName, envVal, err := coscel.ParseEnvVar(string(cosTlv.EventContent))
			if err != nil {
				return nil, err
			}
			cosState.Container.OverriddenEnvVars[envName] = envVal
		case coscel.LaunchSeparatorType:
			seenSeparator = true
		case coscel.MemoryMonitorType:
			enabled := false
			if len(cosTlv.EventContent) == 1 && cosTlv.EventContent[0] == uint8(1) {
				enabled = true
			}
			cosState.HealthMonitoring.MemoryEnabled = &enabled
		default:
			return nil, fmt.Errorf("found unknown COS Event Type %v", cosTlv.EventType)
		}

	}
	return cosState, nil
}
