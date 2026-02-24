package models

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestVMAttestationMarshaling(t *testing.T) {
	tests := []struct {
		name string
		in   *VMAttestation
		want map[string]any
	}{
		{
			name: "TDX Attestation",
			in: &VMAttestation{
				Label:     []byte("test-label"),
				Challenge: []byte("test-challenge"),
				ExtraData: []byte("test-extra"),
				Quote: &VMAttestationQuote{
					TDXCCELQuote: &TDXCCELQuote{
						CCELBootEventLog:  []byte("ccel-data"),
						CELLaunchEventLog: []byte("cel-data"),
						TDQuote:           []byte("td-quote"),
					},
				},
				DeviceReports: []DeviceAttestationReport{{}},
			},
			want: map[string]any{
				"label":      "dGVzdC1sYWJlbA==",
				"challenge":  "dGVzdC1jaGFsbGVuZ2U=",
				"extra_data": "dGVzdC1leHRyYQ==",
				"vm_attestation_quote": map[string]any{
					"tdx_ccel_quote": map[string]any{
						"ccel_boot_event_log":  "Y2NlbC1kYXRh",
						"cel_launch_event_log": "Y2VsLWRhdGE=",
						"td_quote":             "dGQtcXVvdGU=",
					},
				},
				"device_reports": []any{map[string]any{}},
			},
		},
		{
			name: "TPM Attestation",
			in: &VMAttestation{
				Label:     []byte("test-label-tpm"),
				Challenge: []byte("test-challenge-tpm"),
				Quote: &VMAttestationQuote{
					TPMQuote: &TPMQuote{
						PCClientBootEventLog: []byte("pcclient-log"),
						CELLaunchEventLog:    []byte("cel-log"),
						Quotes: []*SignedQuote{
							{
								TPMSAttest: []byte("quote-bytes"),
							},
						},
					},
				},
			},
			want: map[string]any{
				"label":     "dGVzdC1sYWJlbC10cG0=",
				"challenge": "dGVzdC1jaGFsbGVuZ2UtdHBt",
				"vm_attestation_quote": map[string]any{
					"tpm_quote": map[string]any{
						"cel_launch_event_log":    "Y2VsLWxvZw==",
						"endorsement":             nil,
						"pcclient_boot_event_log": "cGNjbGllbnQtbG9n",
						"quotes": []any{
							map[string]any{
								"hash_algorithm": float64(0),
								"pcr_values":     nil,
								"tpms_attest":    "cXVvdGUtYnl0ZXM=",
								"tpmt_signature": nil,
							},
						},
					},
				},
			},
		},
		{
			name: "Empty Quote",
			in: &VMAttestation{
				Label:     []byte("label"),
				Challenge: []byte("challenge"),
				Quote:     &VMAttestationQuote{},
			},
			want: map[string]any{
				"label":                "bGFiZWw=",
				"challenge":            "Y2hhbGxlbmdl",
				"vm_attestation_quote": map[string]any{},
			},
		},
		{
			name: "Empty",
			in:   &VMAttestation{},
			want: map[string]any{
				"label":                nil,
				"challenge":            nil,
				"vm_attestation_quote": nil,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}

			var out VMAttestation
			if err := json.Unmarshal(blob, &out); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}

			if diff := cmp.Diff(tc.in, &out, protocmp.Transform()); diff != "" {
				t.Fatalf("Marshaling roundtrip mismatch (-want +got):\n%s", diff)
			}

			// Check the JSON string output matches our expectation.
			// Unmarshal both into map[string]any to ignore key ordering and formatting
			var gotMap map[string]any
			if err := json.Unmarshal(blob, &gotMap); err != nil {
				t.Fatalf("Failed to unmarshal got JSON: %v", err)
			}

			if diff := cmp.Diff(tc.want, gotMap); diff != "" {
				t.Errorf("JSON mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
