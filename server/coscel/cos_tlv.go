package coscel

import (
	"crypto"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/go-eventlog/cel"
)

const (
	// CELRType indicates the CELR event is a COS content
	// TODO: the value needs to be reserved in the CEL spec
	CELRType uint8 = 80
	// EventPCRIndex is the PCR which should be used for CosEventType events.
	EventPCRIndex = 13
	// EventRTMRIndex is the RTMR to be extended for COS events
	// According to https://uefi.org/specs/UEFI/2.10/38_Confidential_Computing.html
	// CCELMRIndex      TDX Register
	// 0                   MRTD
	// 1                   RTMR[0]
	// 2                   RTMR[1]
	// 3                   RTMR[2]
	// So:
	// 4                   RTMR[3]
	EventRTMRIndex = 3
	// COSCCELMRIndex is the CCMR index to use in eventlog for COS events.
	COSCCELMRIndex = 4
)

// ContentType represent a COS content type in a CEL record content.
type ContentType uint8

// Type for COS nested events
const (
	ImageRefType ContentType = iota
	ImageDigestType
	RestartPolicyType
	ImageIDType
	ArgType
	EnvVarType
	OverrideArgType
	OverrideEnvType
	LaunchSeparatorType
	MemoryMonitorType
)

// COSTLV is a specific event type created for the COS (Google Container-Optimized OS),
// used as a CEL content.
type COSTLV struct {
	EventType    ContentType
	EventContent []byte
}

// GetTLV returns the TLV representation of the COS TLV.
func (c COSTLV) TLV() (cel.TLV, error) {
	data, err := cel.TLV{uint8(c.EventType), c.EventContent}.MarshalBinary()
	if err != nil {
		return cel.TLV{}, err
	}

	return cel.TLV{
		Type:  CELRType,
		Value: data,
	}, nil
}

// GenerateDigest generates the digest for the given COS TLV. The whole TLV struct will
// be marshaled to bytes and feed into the hash algo.
func (c COSTLV) GenerateDigest(hashAlgo crypto.Hash) ([]byte, error) {
	contentTLV, err := c.TLV()
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

// ParseToCOSTLV constructs a CosTlv from t. It will check for the correct COS event
// type, and unmarshal the nested event.
func ParseToCOSTLV(t cel.TLV) (COSTLV, error) {
	if !IsCOSTLV(t) {
		return COSTLV{}, fmt.Errorf("TLV type %v is not a COS event", t.Type)
	}
	nestedEvent := cel.TLV{}
	err := nestedEvent.UnmarshalBinary(t.Value)
	if err != nil {
		return COSTLV{}, err
	}
	return COSTLV{ContentType(nestedEvent.Type), nestedEvent.Value}, nil
}

// IsCOSTLV check whether t is a COS TLV by its Type value.
func IsCOSTLV(t cel.TLV) bool {
	return t.Type == CELRType
}

// FormatEnvVar takes in an environment variable name and its value, run some checks. Concats
// the name and value by '=' and returns it if valid; returns an error if the name or value
// is invalid.
func FormatEnvVar(name string, value string) (string, error) {
	if !utf8.ValidString(name) {
		return "", fmt.Errorf("malformed env name, contains non-utf8 character: [%s]", name)
	}
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("malformed env value, contains non-utf8 character: [%s]", value)
	}
	var envVarNameRegexp = regexp.MustCompile("^[a-zA-Z_][a-zA-Z0-9_]*$")
	if !envVarNameRegexp.MatchString(name) {
		return "", fmt.Errorf("malformed env name [%s], env name must start with an alpha character or '_', followed by a string of alphanumeric characters or '_' (%s)", name, envVarNameRegexp)
	}
	return name + "=" + value, nil
}

// ParseEnvVar takes in environment variable as a string (foo=bar), parses it and returns its name
// and value, or an error if it fails the validation check.
func ParseEnvVar(envvar string) (string, string, error) {
	// switch to strings.Cut when upgrading to go 1.18
	e := strings.SplitN(string(envvar), "=", 2)
	if len(e) < 2 {
		return "", "", fmt.Errorf("malformed env var, doesn't contain '=': [%s]", envvar)
	}

	if _, err := FormatEnvVar(e[0], e[1]); err != nil {
		return "", "", err
	}

	return e[0], e[1], nil
}
