// Package coscel contains the Host COS TLV event type and related functions.
package coscel

import (
	"crypto"
	"fmt"

	"github.com/google/go-eventlog/cel"
)

const (
	// CELRType indicates the CELR event is a Host COS content
	// TODO: the value needs to be reserved in the CEL spec
	CELRType uint8 = 82
	// UserspacePCRIdx is the PCR which should be used for Host.
	UserspacePCRIdx = 19
)

// ContentType represent a Host COS content type in a CEL record content.
type ContentType uint8

// Type for COS nested events.
const (
	CPUPIIDType ContentType = iota
	LaunchSeparatorType
)

// COSTLV is a specific event type created for the Host COS,
// used as a CEL content.
type COSTLV struct {
	EventType    ContentType
	EventContent []byte
}

// TLV returns the TLV representation of the Host COS TLV.
func (c COSTLV) TLV() (cel.TLV, error) {
	data, err := cel.TLV{Type: uint8(c.EventType), Value: c.EventContent}.MarshalBinary()
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

// ParseToCOSTLV constructs a COSTLV from t. It will check for the correct Host COS event
// type, and unmarshal the nested event.
func ParseToCOSTLV(t cel.TLV) (COSTLV, error) {
	if !IsCOSTLV(t) {
		return COSTLV{}, fmt.Errorf("TLV type %v is not a Host COS event", t.Type)
	}
	nestedEvent := cel.TLV{}
	err := nestedEvent.UnmarshalBinary(t.Value)
	if err != nil {
		return COSTLV{}, err
	}
	return COSTLV{ContentType(nestedEvent.Type), nestedEvent.Value}, nil
}

// IsCOSTLV check whether t is a Host COS TLV by its Type value.
func IsCOSTLV(t cel.TLV) bool {
	return t.Type == CELRType
}
