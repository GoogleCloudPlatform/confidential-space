package extract

import (
	"bytes"
	"encoding/hex"
	"fmt"

	attestpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	statepb "github.com/google/go-eventlog/proto/state"
	elpb "github.com/google/go-eventlog/proto/state"
)

var acpiLabel = []byte("ACPI DATA") // EV_POSTCODE_INFO_ACPI_DATA
const acpiEventType = uint32(0xA)   // EV_PLATFORM_CONFIG_FLAGS

// VerifyACPIDataAgainstLog validates that the expected ACPI digests exist exactly
// in the verified UEFI event log, and that no other ACPI tables were measured.
func VerifyACPIDataAgainstLog(acpiData *attestpb.AcpiData, fls *elpb.FirmwareLogState) error {
	if acpiData == nil {
		return fmt.Errorf("acpiData is nil")
	}
	if fls == nil {
		return fmt.Errorf("FirmwareLogState is nil")
	}

	cryptoHash, err := statepb.HashAlgo(fls.GetHash()).CryptoHash()
	if err != nil {
		return fmt.Errorf("failed to resolve crypto hash algorithm from event log: %w", err)
	}

	fields := []struct {
		name string
		data []byte
	}{
		{name: "table_loader", data: acpiData.GetTableLoader()},
		{name: "rsdp", data: acpiData.GetRsdp()},
		{name: "tables", data: acpiData.GetTables()},
	}

	extractedDigests := make(map[string]string)
	for _, field := range fields {
		if len(field.data) == 0 {
			return fmt.Errorf("missing required reference data for ACPI field: %q", field.name)
		}
		hasher := cryptoHash.New()
		hasher.Write(field.data)
		digestHex := hex.EncodeToString(hasher.Sum(nil))
		extractedDigests[digestHex] = field.name
	}

	activeExpectedCount := len(extractedDigests)

	acpiEventCount := 0

	for _, event := range fls.GetRawEvents() {
		t := event.GetUntrustedType()

		isTargetType := t == acpiEventType

		if !isTargetType {
			continue
		}

		eventData := event.GetData()
		isACPI := bytes.Contains(eventData, acpiLabel)

		if !isACPI {
			continue
		}

		acpiEventCount++

		digestHex := hex.EncodeToString(event.GetDigest())
		if _, exists := extractedDigests[digestHex]; !exists {
			return fmt.Errorf("unexpected ACPI event detected in log with digest: %s", digestHex)
		}
		delete(extractedDigests, digestHex)
	}

	// Exactly one measurement must be found for each expected ACPI field
	if len(extractedDigests) > 0 {
		return fmt.Errorf("validation failed, missing expected ACPI measurements in event log: %v", extractedDigests)
	}

	if acpiEventCount != activeExpectedCount {
		return fmt.Errorf("expected exactly %d ACPI events, but found %d", activeExpectedCount, acpiEventCount)
	}

	return nil
}
