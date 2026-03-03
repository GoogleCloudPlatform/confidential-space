// Package labels contains structs for evidence types used by workload attestation.
package labels

const (
	// WorkloadAttestation is the label used by Confidential Space.
	WorkloadAttestation = "WORKLOAD_ATTESTATION"

	// KeyAttestation is the label used for Key Attestation.
	KeyAttestation = "KEY_ATTESTATION"

	// HostAttestation is the label used for Host Attestation.
	HostAttestation = "HOST_ATTESTATION"
)
