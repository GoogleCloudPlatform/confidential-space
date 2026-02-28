// Package data provides data related to confidential space image validation.
package data

import (
	"crypto/x509"
	"encoding/pem"

	"google3/base/go/log"

	_ "embed"
)

func parseCertificateDER(certDER []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Fatalf("Unable to parse Certificate: %v", err)
	}
	return cert
}

func parseCertificatePEM(certPEM []byte) *x509.Certificate {
	derBytes := convertPEMToDER(certPEM)
	return parseCertificateDER(derBytes)
}

func convertPEMToDER(certPEM []byte) []byte {
	block, rest := pem.Decode(certPEM)
	if block == nil {
		log.Fatal("Unable to decode certificate as PEM")
	}
	if block.Type != "CERTIFICATE" {
		log.Fatalf("Unexpected PEM type: %q", block.Type)
	}
	if len(rest) > 0 {
		log.Fatal("Unexpected trailing data in certificate file")
	}
	return block.Bytes
}

// cosDBv10CertPEM is the cert for the COS Secure Boot signing key.
//
//go:embed cos_db_v10.pem
var cosDBv10CertPEM []byte

// COSDBv10Cert is the raw byte representation of the Container-optimized OS DB cert.
var COSDBv10Cert = parseCertificatePEM(cosDBv10CertPEM)

// cosDBv20250203CertPEM is the cert for the COS Secure Boot signing key.
//
//go:embed cos_db_v20250203.pem
var cosDBv20250203CertPEM []byte

// COSDBv20250203Cert is the raw byte representation of the Container-optimized OS DB cert.
var COSDBv20250203Cert = parseCertificatePEM(cosDBv20250203CertPEM)

// cosDBv20251004CertPEM is the cert for the COS Secure Boot signing key.
//
//go:embed cos_db_v20251004.pem
var cosDBv20251004CertPEM []byte

// COSDBv20251004Cert is the raw byte representation of the Container-optimized OS DB cert.
var COSDBv20251004Cert = parseCertificatePEM(cosDBv20251004CertPEM)
