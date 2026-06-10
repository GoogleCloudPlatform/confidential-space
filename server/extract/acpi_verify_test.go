package extract

import (
	"crypto"
	"testing"

	attestpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	elpb "github.com/google/go-eventlog/proto/state"
)

func TestVerifyACPIData(t *testing.T) {
	acpiLabel := []byte("ACPI DATA")

	mockRDSP := []byte("my custom rsdp tables content")
	mockTables := []byte("my custom combined acpi tables content")
	mockLoader := []byte("my custom loaded acpi table list")

	cryptoHash := crypto.SHA384
	hasher := cryptoHash.New()

	hasher.Write(mockRDSP)
	rsdpDigest := hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(mockTables)
	tablesDigest := hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(mockLoader)
	loaderDigest := hasher.Sum(nil)

	t.Run("SuccessMatchingACPIDigests", func(t *testing.T) {
		mockACPIData := &attestpb.AcpiData{
			Rsdp:        mockRDSP,
			Tables:      mockTables,
			TableLoader: mockLoader,
		}

		extState := &elpb.FirmwareLogState{
			Hash: elpb.HashAlgo_SHA384,
			RawEvents: []*elpb.Event{
				{
					UntrustedType: 0xA,
					Data:          acpiLabel,
					Digest:        loaderDigest,
				},
				{
					UntrustedType: 0xA,
					Data:          acpiLabel,
					Digest:        rsdpDigest,
				},
				{
					UntrustedType: 0xA,
					Data:          acpiLabel,
					Digest:        tablesDigest,
				},
			},
		}

		if err := VerifyACPIDataAgainstLog(mockACPIData, extState); err != nil {
			t.Errorf("VerifyACPIDataAgainstLog(%v, %v) = %v, want nil", mockACPIData, extState, err)
		}
	})

	t.Run("FailureExtraneousInjection", func(t *testing.T) {
		mockACPIData := &attestpb.AcpiData{
			Rsdp:        mockRDSP,
			Tables:      mockTables,
			TableLoader: mockLoader,
		}

		extState := &elpb.FirmwareLogState{
			Hash: elpb.HashAlgo_SHA384,
			RawEvents: []*elpb.Event{
				{
					UntrustedType: 0xA,
					Data:          acpiLabel,
					Digest:        loaderDigest,
				},
				{
					UntrustedType: 0xA,
					Data:          acpiLabel,
					Digest:        rsdpDigest,
				},
				{
					UntrustedType: 0xA,
					Data:          acpiLabel,
					Digest:        tablesDigest,
				},
				{
					UntrustedType: 0xA,
					Data:          acpiLabel,
					Digest:        []byte("bad ACPI table"),
				},
			},
		}

		if err := VerifyACPIDataAgainstLog(mockACPIData, extState); err == nil {
			t.Errorf("VerifyACPIDataAgainstLog(%v, %v) = nil, want error due to extraneous ACPI injection", mockACPIData, extState)
		}
	})

	t.Run("FailureEmptyFieldBypass", func(t *testing.T) {
		mockACPIData := &attestpb.AcpiData{
			Rsdp:        nil,
			Tables:      mockTables,
			TableLoader: mockLoader,
		}

		extState := &elpb.FirmwareLogState{
			Hash: elpb.HashAlgo_SHA384,
			RawEvents: []*elpb.Event{
				{
					UntrustedType: 0xA,
					Data:          acpiLabel,
					Digest:        loaderDigest,
				},
				{
					UntrustedType: 0xA,
					Data:          acpiLabel,
					Digest:        tablesDigest,
				},
			},
		}

		if err := VerifyACPIDataAgainstLog(mockACPIData, extState); err == nil {
			t.Errorf("VerifyACPIDataAgainstLog(%v, %v) = nil, want error due to missing required reference data payload", mockACPIData, extState)
		}
	})

	t.Run("FailureMissingMatch", func(t *testing.T) {
		mockACPIData := &attestpb.AcpiData{
			Rsdp:        mockRDSP,
			Tables:      mockTables,
			TableLoader: mockLoader,
		}

		extState := &elpb.FirmwareLogState{
			Hash: elpb.HashAlgo_SHA384,
			RawEvents: []*elpb.Event{
				{
					UntrustedType: 0xA,
					Data:          acpiLabel,
					Digest:        loaderDigest,
				},
				{
					UntrustedType: 0xA,
					Data:          acpiLabel,
					Digest:        rsdpDigest,
				},
				{
					UntrustedType: 0xA,
					Data:          acpiLabel,
					Digest:        []byte("bad tables digest"),
				},
			},
		}

		if err := VerifyACPIDataAgainstLog(mockACPIData, extState); err == nil {
			t.Errorf("VerifyACPIDataAgainstLog(%v, %v) = nil, want error on unmatched ACPI tables digest", mockACPIData, extState)
		}
	})

	t.Run("SuccessWithOtherEvents", func(t *testing.T) {
		mockACPIData := &attestpb.AcpiData{
			Rsdp:        mockRDSP,
			Tables:      mockTables,
			TableLoader: mockLoader,
		}

		extState := &elpb.FirmwareLogState{
			Hash: elpb.HashAlgo_SHA384,
			RawEvents: []*elpb.Event{
				{
					UntrustedType: 0x80000001, // SecureBoot variables type (ignored)
					Data:          []byte("PK"),
					Digest:        []byte("non-matching digest"),
				},
				{
					UntrustedType: 0xA, // Target type, matches table_loader
					Data:          acpiLabel,
					Digest:        loaderDigest,
				},
				{
					UntrustedType: 0x4, // Separation event (ignored)
					Data:          nil,
					Digest:        []byte("non-matching digest"),
				},
				{
					UntrustedType: 0xA, // Target type, matches rsdp
					Data:          acpiLabel,
					Digest:        rsdpDigest,
				},
				{
					UntrustedType: 0xA, // Target type, matches tables
					Data:          acpiLabel,
					Digest:        tablesDigest,
				},
			},
		}

		if err := VerifyACPIDataAgainstLog(mockACPIData, extState); err != nil {
			t.Errorf("VerifyACPIDataAgainstLog(%v, %v) = %v, want nil with unrelated events present", mockACPIData, extState, err)
		}
	})
}
