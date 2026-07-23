// Package extract contains functions to extract information from the COS event log.
package extract

import (
	"bytes"
	"fmt"

	"github.com/GoogleCloudPlatform/confidential-space/server/coscel"
	attestpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	"github.com/google/go-eventlog/cel"
	"github.com/google/go-eventlog/register"
	"google.golang.org/protobuf/proto"
	pb "github.com/google/go-tpm-tools/proto/attest"
)

// Options contains the options for parsing the COS event log.
type Options struct {
	PopulateGpuDeviceState bool // Whether to populate the GPU device state default is false.
}

// ParseCOSCEL takes an encoded Attested COS CEL and MR bank, replays the CEL against the MRs,
// and returns the AttestedCosState.
func ParseCOSCEL(cosEventLog []byte, p register.MRBank, opts Options) (*pb.AttestedCosState, error) {
	switch p.(type) {
	case register.PCRBank:
		return getCOSStateFromCEL(cosEventLog, p, cel.PCRType, opts)
	case register.RTMRBank:
		return getCOSStateFromCEL(cosEventLog, p, cel.CCMRType, opts)
	default:
		return nil, fmt.Errorf("unknown register type %T", p)
	}
}

func getCOSStateFromCEL(rawCanonicalEventLog []byte, register register.MRBank, trustingRegisterType cel.MRType, opts Options) (*pb.AttestedCosState, error) {
	decodedCEL, err := cel.DecodeToCEL(bytes.NewBuffer(rawCanonicalEventLog))
	if err != nil {
		return nil, err
	}
	// Validate the COS event log first.
	if err := decodedCEL.Replay(register); err != nil {
		return nil, err
	}

	cosState, err := VerifiedCOSState(decodedCEL, uint8(trustingRegisterType), opts)
	if err != nil {
		return nil, err
	}

	return cosState, err
}

// VerifiedCOSState returns the AttestedCosState from the given event log.
func VerifiedCOSState(eventLog cel.CEL, registerType uint8, opts Options) (*pb.AttestedCosState, error) {
	cosState := &pb.AttestedCosState{}

	// Initialize a default container (handles backward compatibility for old single-container logs)
	defaultContainer := &pb.ContainerState{
		Args:              make([]string, 0),
		EnvVars:           make(map[string]string),
		OverriddenEnvVars: make(map[string]string),
	}

	cosState.Containers = []*pb.ContainerState{defaultContainer}

	currentContainer := defaultContainer

	cosState.HealthMonitoring = &pb.HealthMonitoringState{}
	cosState.GpuDeviceState = &pb.GpuDeviceState{}

	seenSeparator := false
	for _, record := range eventLog.Records() {
		if uint8(record.IndexType) != registerType {
			return nil, fmt.Errorf("expect registerType: %d, but get %d in a CEL record", registerType, record.IndexType)
		}

		switch record.IndexType {
		case cel.PCRType:
			if record.Index != coscel.EventPCRIndex {
				return nil, fmt.Errorf("found unexpected PCR %d in COS CEL log", record.Index)
			}
		case cel.CCMRType:
			if record.Index != coscel.COSCCELMRIndex {
				return nil, fmt.Errorf("found unexpected CCELMR %d in COS CEL log", record.Index)
			}
		default:
			return nil, fmt.Errorf("unknown COS CEL log index type %d", record.IndexType)
		}

		// The Content.Type is not verified at this point, so we have to fail
		// if we see any events that we do not understand. This ensures that
		// we either verify the digest of event event in this PCR/RTMA, or we
		// fail to replay the event log.
		// TODO: See if we can fix this to have the Content Type be verified.
		cosTlv, err := coscel.ParseToCOSTLV(record.Content)
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
		case coscel.ContainerSeparatorType:
			// If default container is already populated with an image (meaning we are on 2nd container)
			// Or Create a new one every time we see this event
			if currentContainer.GetImageReference() != "" || currentContainer.GetImageDigest() != "" {
				currentContainer = &pb.ContainerState{
					Args:              make([]string, 0),
					EnvVars:           make(map[string]string),
					OverriddenEnvVars: make(map[string]string),
				}
				cosState.Containers = append(cosState.Containers, currentContainer)
			}
		case coscel.ImageRefType:
			if currentContainer.GetImageReference() != "" {
				return nil, fmt.Errorf("found more than one ImageRef event")
			}
			currentContainer.ImageReference = string(cosTlv.EventContent)

		case coscel.ImageDigestType:
			if currentContainer.GetImageDigest() != "" {
				return nil, fmt.Errorf("found more than one ImageDigest event")
			}
			currentContainer.ImageDigest = string(cosTlv.EventContent)

		case coscel.RestartPolicyType:
			restartPolicy, ok := pb.RestartPolicy_value[string(cosTlv.EventContent)]
			if !ok {
				return nil, fmt.Errorf("unknown restart policy in COS eventlog: %s", string(cosTlv.EventContent))
			}
			currentContainer.RestartPolicy = pb.RestartPolicy(restartPolicy)

		case coscel.ImageIDType:
			if currentContainer.GetImageId() != "" {
				return nil, fmt.Errorf("found more than one ImageId event")
			}
			currentContainer.ImageId = string(cosTlv.EventContent)

		case coscel.EnvVarType:
			envName, envVal, err := coscel.ParseEnvVar(string(cosTlv.EventContent))
			if err != nil {
				return nil, err
			}
			currentContainer.EnvVars[envName] = envVal

		case coscel.ArgType:
			currentContainer.Args = append(currentContainer.Args, string(cosTlv.EventContent))

		case coscel.OverrideArgType:
			currentContainer.OverriddenArgs = append(currentContainer.OverriddenArgs, string(cosTlv.EventContent))

		case coscel.OverrideEnvType:
			envName, envVal, err := coscel.ParseEnvVar(string(cosTlv.EventContent))
			if err != nil {
				return nil, err
			}
			currentContainer.OverriddenEnvVars[envName] = envVal
		case coscel.LaunchSeparatorType:
			seenSeparator = true
		case coscel.MemoryMonitorType:
			enabled := false
			if len(cosTlv.EventContent) == 1 && cosTlv.EventContent[0] == uint8(1) {
				enabled = true
			}
			cosState.HealthMonitoring.MemoryEnabled = &enabled
		case coscel.GpuCCModeType:
			if cosState.GpuDeviceState == nil {
				cosState.GpuDeviceState = &pb.GpuDeviceState{}
			}
			ccMode, ok := pb.GPUDeviceCCMode_value[string(cosTlv.EventContent)]
			if !ok {
				return nil, fmt.Errorf("unknown GPU device CC mode in COS eventlog: %s", string(cosTlv.EventContent))
			}
			cosState.GpuDeviceState.CcMode = pb.GPUDeviceCCMode(ccMode)
		case coscel.GPUDeviceAttestationBindingType:
			if opts.PopulateGpuDeviceState {
				report := &attestpb.NvidiaAttestationReport{}
				if err := proto.Unmarshal(cosTlv.EventContent, report); err != nil {
					return nil, fmt.Errorf("failed to unmarshal GPU attestation report: %v", err)
				}
				cosState.GpuDeviceState.NvidiaAttestationReport = report
			}

		default:
			return nil, fmt.Errorf("found unknown COS Event Type %v", cosTlv.EventType)
		}

	}
	return cosState, nil
}
