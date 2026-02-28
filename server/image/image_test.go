package image

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	tpb "google.golang.org/protobuf/types/known/timestamppb"
	"github.com/GoogleCloudPlatform/confidential-space/server/image/data"
	"github.com/google/go-cmp/cmp"

	"google.golang.org/protobuf/testing/protocmp"
	attestpb "github.com/google/go-tpm-tools/proto/attest"

	rimpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/image_database"
)

const (
	testGoldenKeyFoo = "cmdline-foo"
	testGoldenKeyBar = "cmdline-bar"
)

func TestKnownCertificate(t *testing.T) {
	tests := []struct {
		name      string
		certProto rimpb.ImageDatabase_CCKnownCertificates
		want      *x509.Certificate
	}{
		{
			name:      "Known certificate COS_DB_V10",
			certProto: rimpb.ImageDatabase_COS_DB_V10,
			want:      data.COSDBv10Cert,
		},
		{
			name:      "Known certificate COS_DB_V20250203",
			certProto: rimpb.ImageDatabase_COS_DB_V20250203,
			want:      data.COSDBv20250203Cert,
		},
		{
			name:      "Known certificate COS_DB_V20251004",
			certProto: rimpb.ImageDatabase_COS_DB_V20251004,
			want:      data.COSDBv20251004Cert,
		},
		{
			name:      "Unknown certificate",
			certProto: rimpb.ImageDatabase_UNSPECIFIED_CERT,
			want:      nil,
		},
	}

	for _, tc := range tests {
		got := knownCertificate(tc.certProto)
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("KnownCertificate(%+v) returned unexpected diff (-want +got):\n%s", tc.certProto, diff)
		}
	}
}

func TestGetGoldenValues(t *testing.T) {
	db := testDatabase(t)
	ms := &attestpb.MachineState{
		LinuxKernel: &attestpb.LinuxKernelState{
			CommandLine: testGoldenKeyFoo,
		},
	}

	want, ok := db.GetGoldenValues()[testGoldenKeyFoo]
	if !ok {
		t.Fatalf("testDatabase() did not contain testGoldenKeyFoo")
	}

	got, err := GetGoldenValues(ms, db)
	if err != nil {
		t.Fatalf("GetGoldenValues() failed: %v", err)
	}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("GetGoldenValues() returned unexpected diff (-want +got):\n%s", diff)
	}
}

func TestGetGoldenValuesErrors(t *testing.T) {
	validMs := &attestpb.MachineState{
		LinuxKernel: &attestpb.LinuxKernelState{
			CommandLine: testGoldenKeyFoo,
		},
	}

	testcases := []struct {
		name    string
		ms      *attestpb.MachineState
		imageDb *rimpb.ImageDatabase
	}{
		{
			name:    "nil MachineState",
			ms:      nil,
			imageDb: testDatabase(t),
		},
		{
			name:    "nil ImageDB",
			ms:      validMs,
			imageDb: nil,
		},
		{
			name: "nil LinuxKernelState",
			ms: &attestpb.MachineState{
				LinuxKernel: nil,
			},
			imageDb: testDatabase(t),
		},
		{
			name: "not present in ImageDB",
			ms:   validMs,
			imageDb: &rimpb.ImageDatabase{
				GoldenValues: map[string]*rimpb.ImageDatabase_ImageGoldenEntry{
					"other-cmdline": buildGoldenEntry("test-bar", false, 3, 5678),
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GetGoldenValues(tc.ms, tc.imageDb)
			if err == nil {
				t.Errorf("Expected error from GetGoldenValues(), got nil")
			}
		})
	}
}

func TestValidateImageBaseValues(t *testing.T) {
	sbState := &attestpb.SecureBootState{
		Enabled: true,
		Db: &attestpb.Database{
			Certs: []*attestpb.Certificate{
				&attestpb.Certificate{
					Representation: &attestpb.Certificate_Der{
						Der: data.COSDBv20251004Cert.Raw,
					},
				},
			},
		},
	}

	imageDB := testDatabase(t)

	err := validateBaseValues(sbState, 3, imageDB)
	if err != nil {
		t.Errorf("validateImageBaseValues() failed: %v", err)
	}
}

func TestValidateImageBaseValuesErrors(t *testing.T) {
	validSB := &attestpb.SecureBootState{
		Enabled: true,
		Db: &attestpb.Database{
			Certs: []*attestpb.Certificate{
				&attestpb.Certificate{
					Representation: &attestpb.Certificate_Der{
						Der: data.COSDBv20251004Cert.Raw,
					},
				},
			},
		},
	}

	validImageDB := testDatabase(t)
	validImageBaseVersion := uint32(3)

	testcases := []struct {
		name             string
		sb               *attestpb.SecureBootState
		imageBaseVersion uint32
		db               *rimpb.ImageDatabase
		wantErrStr       string
	}{
		{
			name: "SecureBoot not enabled",
			sb: &attestpb.SecureBootState{
				Enabled: false,
				Db: &attestpb.Database{
					Certs: []*attestpb.Certificate{
						&attestpb.Certificate{
							Representation: &attestpb.Certificate_Der{
								Der: data.COSDBv20251004Cert.Raw,
							},
						},
					},
				},
			},
			db:               validImageDB,
			imageBaseVersion: validImageBaseVersion,
			wantErrStr:       "SecureBoot is not enabled",
		},
		{
			name:             "invalid image base version",
			sb:               validSB,
			db:               validImageDB,
			imageBaseVersion: 10,
			wantErrStr:       "image version",
		},
		{
			name: "nonempty SecureBoot DB hashes",
			sb: &attestpb.SecureBootState{
				Enabled: true,
				Db: &attestpb.Database{
					Certs: []*attestpb.Certificate{
						&attestpb.Certificate{
							Representation: &attestpb.Certificate_Der{
								Der: data.COSDBv20251004Cert.Raw,
							},
						},
					},
					Hashes: [][]byte{[]byte("fake hash")},
				},
			},
			db:               validImageDB,
			imageBaseVersion: validImageBaseVersion,
			wantErrStr:       "hashes",
		},
		{
			name: "multiple SecureBoot DB certs",
			sb: &attestpb.SecureBootState{
				Enabled: true,
				Db: &attestpb.Database{
					Certs: []*attestpb.Certificate{
						&attestpb.Certificate{
							Representation: &attestpb.Certificate_Der{
								Der: data.COSDBv20251004Cert.Raw,
							},
						},
						&attestpb.Certificate{
							Representation: &attestpb.Certificate_Der{
								Der: data.COSDBv20251004Cert.Raw,
							},
						},
					},
				},
			},
			db:               validImageDB,
			imageBaseVersion: validImageBaseVersion,
			wantErrStr:       "expected one",
		},
		{
			name: "multiple known certs",
			sb:   validSB,
			db: &rimpb.ImageDatabase{
				ImageBaseValues: map[uint32]*rimpb.ImageDatabase_ImageBaseEntry{
					3: &rimpb.ImageDatabase_ImageBaseEntry{
						Db: &rimpb.ImageDatabase_CCDatabase{
							KnownCertificates: []rimpb.ImageDatabase_CCKnownCertificates{
								rimpb.ImageDatabase_COS_DB_V20251004,
								rimpb.ImageDatabase_COS_DB_V20250203,
							},
						},
					},
				},
			},
			imageBaseVersion: validImageBaseVersion,
			wantErrStr:       "only have one known cert",
		},
		{
			name: "unknown certificate",
			sb:   validSB,
			db: &rimpb.ImageDatabase{
				ImageBaseValues: map[uint32]*rimpb.ImageDatabase_ImageBaseEntry{
					3: &rimpb.ImageDatabase_ImageBaseEntry{
						Db: &rimpb.ImageDatabase_CCDatabase{
							KnownCertificates: []rimpb.ImageDatabase_CCKnownCertificates{
								rimpb.ImageDatabase_UNSPECIFIED_CERT,
							},
						},
					},
				},
			},
			imageBaseVersion: validImageBaseVersion,
			wantErrStr:       "does not have a known certificate",
		},
		{
			name: "non-DER secure boot cert",
			sb: &attestpb.SecureBootState{
				Enabled: true,
				Db: &attestpb.Database{
					Certs: []*attestpb.Certificate{
						&attestpb.Certificate{
							Representation: &attestpb.Certificate_WellKnown{
								WellKnown: attestpb.WellKnownCertificate_MS_WINDOWS_PROD_PCA_2011,
							},
						},
					},
				},
			},
			db:               validImageDB,
			imageBaseVersion: validImageBaseVersion,
			wantErrStr:       "not a DER certificate",
		},
		{
			name: "mismatched certs",
			sb: &attestpb.SecureBootState{
				Enabled: true,
				Db: &attestpb.Database{
					Certs: []*attestpb.Certificate{
						&attestpb.Certificate{
							Representation: &attestpb.Certificate_Der{
								Der: data.COSDBv20250203Cert.Raw,
							},
						},
					},
				},
			},
			db:               validImageDB,
			imageBaseVersion: validImageBaseVersion,
			wantErrStr:       "did not match the DER of the expected known cert",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBaseValues(tc.sb, tc.imageBaseVersion, tc.db)
			if err == nil {
				t.Fatalf("Expected error from validateImageBaseValues(), got nil")
			}

			if !strings.Contains(err.Error(), tc.wantErrStr) {
				t.Errorf("validateImageBaseValues() did not contain expected error string: %v, want %q", err, tc.wantErrStr)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	validMs := &attestpb.MachineState{
		LinuxKernel: &attestpb.LinuxKernelState{
			CommandLine: testGoldenKeyFoo,
		},
		SecureBoot: &attestpb.SecureBootState{
			Enabled: true,
			Db: &attestpb.Database{
				Certs: []*attestpb.Certificate{
					&attestpb.Certificate{
						Representation: &attestpb.Certificate_Der{
							Der: data.COSDBv20251004Cert.Raw,
						},
					},
				},
			},
		},
	}

	imageDB := testDatabase(t)

	wantEntry := buildGoldenEntry("test-foo", true, 3, 1234,
		rimpb.ImageDatabase_LATEST,
		rimpb.ImageDatabase_STABLE,
		rimpb.ImageDatabase_USABLE,
	)

	got, err := Validate(validMs, imageDB)
	if err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
	if diff := cmp.Diff(wantEntry, got, protocmp.Transform()); diff != "" {
		t.Errorf("Validate() returned unexpected diff (-want +got):\n%s", diff)
	}
}

func testDatabase(t *testing.T) *rimpb.ImageDatabase {
	t.Helper()

	nbf := time.Date(2000, time.March, 1, 0, 0, 0, 0, time.UTC)

	return &rimpb.ImageDatabase{
		GoldenValues: map[string]*rimpb.ImageDatabase_ImageGoldenEntry{
			// Hardened.
			testGoldenKeyFoo: buildGoldenEntry("test-foo", true, 3, 1234,
				rimpb.ImageDatabase_LATEST,
				rimpb.ImageDatabase_STABLE,
				rimpb.ImageDatabase_USABLE,
			),
			// Debug.
			testGoldenKeyBar: buildGoldenEntry("test-bar", false, 3, 5678),
		},
		ServiceBasePolicy: &rimpb.ImageDatabase_ServiceBasePolicy{
			EarliestCertIssueTime: &tpb.Timestamp{
				// Use an arbitrarily early date.
				Seconds: nbf.Unix(),
			},
		},
		ImageBaseValues: map[uint32]*rimpb.ImageDatabase_ImageBaseEntry{
			3: &rimpb.ImageDatabase_ImageBaseEntry{
				Db: &rimpb.ImageDatabase_CCDatabase{
					KnownCertificates: []rimpb.ImageDatabase_CCKnownCertificates{
						rimpb.ImageDatabase_COS_DB_V20251004,
					},
				},
			},
		},
	}
}

func buildGoldenEntry(releaseName string, hardened bool, imageBaseVersion uint32, swversion uint32, labels ...rimpb.ImageDatabase_AttributeLabel) *rimpb.ImageDatabase_ImageGoldenEntry {
	return &rimpb.ImageDatabase_ImageGoldenEntry{
		ImageReleaseName: releaseName,
		IsHardened:       hardened,
		ImageBaseVersion: imageBaseVersion,
		Swversion:        swversion,
		AttributeLabels:  labels,
	}
}
