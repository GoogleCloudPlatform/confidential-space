#!/bin/bash

PARENT_DIR=$(dirname "${PWD}")

source config_env.sh
source common.sh

set_gcp_project "${UWEAR_PROJECT_ID}"

cat << 'EOF' > "${PARENT_DIR}"/src/uwear/workload.go
// Simple workload that connects to a TLS session. 
// Receives a token via the session
// Validates the PKI token is signed by Google.
// Verifies the claims returned (image digest, hardware, software, aud etc.)
// Verifies the nonce equals the TLS Exported Keying Material hash.
// If the token is valid, it sends back the sensitive data via the TLS session.


package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

const (
	mySensitiveDataFile = "./phi_sleep_data"
	rootCertificateFile = "./confidential_space_root.pem"
	ipAddrEnvVar        = "remote_ip_addr"
	opaPolicy           = `
	package confidential_space

	import rego.v1

	default allow := false
	default hw_verified := false
	default image_digest_verified := false
	default audience_verified := false
	default nonce_verified := false
	default issuer_verified := false
	default secboot_verified := false
	default sw_name_verified := false

	allow if {
		hw_verified
		image_digest_verified
		audience_verified
		nonce_verified
		issuer_verified
		secboot_verified
		sw_name_verified
	}

	hw_verified if input.hwmodel in data.allowed_hwmodel
	image_digest_verified if input.submods.container.image_digest in data.allowed_submods_container_image_digest
	audience_verified if input.aud in data.allowed_aud
	issuer_verified if input.iss in data.allowed_issuer
	secboot_verified if input.secboot in data.allowed_secboot
	sw_name_verified if input.swname in data.allowed_sw_name
	nonce_verified if {
		input.eat_nonce == "%s"
	}
	`
)

func readFile(filename string) ([]byte, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Failed to read in sensitive data file")
		return nil, err
	}

	return file, nil
}

// ValidatePKIToken validates the PKI token returned from the attestation service is valid.
// Returns a valid jwt.Token or returns an error if invalid.
func ValidatePKIToken(attestationToken string, ekm string) (jwt.Token, error) {
	// IMPORTANT: The attestation token should be considered untrusted until the certificate chain and
	// the signature is verified.
	rawRootCertificate, err := readFile(rootCertificateFile)
	if err != nil {
		return jwt.Token{}, fmt.Errorf("readFile(%v) - failed to read root certificate: %w", rootCertificateFile, err)
	}

	storedRootCert, err := DecodeAndParseCertificate(string(rawRootCertificate))
	if err != nil {
		return jwt.Token{}, fmt.Errorf("DecodeAndParseCertificate(string) - failed to decode and parse root certificate: %w", err)
	}

	jwtHeaders, err := ExtractJWTHeaders(attestationToken)
	if err != nil {
		return jwt.Token{}, fmt.Errorf("ExtractJWTHeaders(token) returned error: %v", err)
	}

	if jwtHeaders["alg"] != "RS256" {
		return jwt.Token{}, fmt.Errorf("ValidatePKIToken(string, *attestpb.Attestation, *v1mainpb.VerifyAttestationRequest) - got Alg: %v, want: %v", jwtHeaders["alg"], "RS256")
	}

	// Additional Check: Validate the ALG in the header matches the certificate SPKI.
	// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.7
	// This is included in golangs jwt.Parse function

	x5cHeaders := jwtHeaders["x5c"].([]any)
	certificates, err := ExtractCertificatesFromX5CHeader(x5cHeaders)
	if err != nil {
		return jwt.Token{}, fmt.Errorf("ExtractCertificatesFromX5CHeader(x5cHeaders) returned error: %v", err)
	}

	// Verify the leaf certificate signature algorithm is an RSA key
	if certificates.LeafCert.SignatureAlgorithm != x509.SHA256WithRSA {
		return jwt.Token{}, fmt.Errorf("leaf certificate signature algorithm is not SHA256WithRSA")
	}

	// Verify the leaf certificate public key algorithm is RSA
	if certificates.LeafCert.PublicKeyAlgorithm != x509.RSA {
		return jwt.Token{}, fmt.Errorf("leaf certificate public key algorithm is not RSA")
	}

	// Verify the storedRootCertificate is the same as the root certificate returned in the token
	// storedRootCertificate is downloaded from the confidential computing well known endpoint
	// https://confidentialcomputing.googleapis.com/.well-known/attestation-pki-root
	err = CompareCertificates(*storedRootCert, *certificates.RootCert)
	if err != nil {
		return jwt.Token{}, fmt.Errorf("failed to verify certificate chain: %v", err)
	}

	err = VerifyCertificateChain(certificates)
	if err != nil {
		return jwt.Token{}, fmt.Errorf("VerifyCertificateChain(string, *attestpb.Attestation, *v1mainpb.VerifyAttestationRequest) - error verifying x5c chain: %v", err)
	}

	keyFunc := func(token *jwt.Token) (any, error) {
		return certificates.LeafCert.PublicKey, nil
	}

	verifiedJWT, err := jwt.Parse(attestationToken, keyFunc)
	return *verifiedJWT, err
}

// ExtractJWTHeaders parses the JWT and returns the headers.
func ExtractJWTHeaders(token string) (map[string]any, error) {
	parser := &jwt.Parser{}

	// The claims returned from the token are unverified at this point
	// Do not use the claims until the algorithm, certificate chain verification and root certificate
	// comparison is successful
	unverifiedClaims := &jwt.MapClaims{}
	parsedToken, _, err := parser.ParseUnverified(token, unverifiedClaims)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse claims token: %v", err)
	}

	return parsedToken.Header, nil
}

// PKICertificates contains the certificates extracted from the x5c header.
type PKICertificates struct {
	LeafCert         *x509.Certificate
	IntermediateCert *x509.Certificate
	RootCert         *x509.Certificate
}

// ExtractCertificatesFromX5CHeader extracts the certificates from the given x5c header.
func ExtractCertificatesFromX5CHeader(x5cHeaders []any) (PKICertificates, error) {
	if x5cHeaders == nil {
		return PKICertificates{}, fmt.Errorf("VerifyAttestation(string, *attestpb.Attestation, *v1mainpb.VerifyAttestationRequest) - x5c header not set")
	}

	x5c := []string{}
	for _, header := range x5cHeaders {
		x5c = append(x5c, header.(string))
	}

	// x5c header should have at least 3 certificates - leaf, intermediate and root
	if len(x5c) < 3 {
		return PKICertificates{}, fmt.Errorf("not enough certificates in x5c header, expected 3 certificates, but got %v", len(x5c))
	}

	leafCert, err := DecodeAndParseCertificate(x5c[0])
	if err != nil {
		return PKICertificates{}, fmt.Errorf("cannot parse intermediate certificate: %v", err)
	}

	intermediateCert, err := DecodeAndParseCertificate(x5c[1])
	if err != nil {
		return PKICertificates{}, fmt.Errorf("cannot parse intermediate certificate: %v", err)
	}

	rootCert, err := DecodeAndParseCertificate(x5c[2])
	if err != nil {
		return PKICertificates{}, fmt.Errorf("cannot parse intermediate certificate: %v", err)
	}

	certificates := PKICertificates{
		LeafCert:         leafCert,
		IntermediateCert: intermediateCert,
		RootCert:         rootCert,
	}
	return certificates, nil
}

// DecodeAndParseCertificate decodes the given PEM certificate string and parses it into an x509 certificate.
func DecodeAndParseCertificate(certificate string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certificate))
	if block == nil {
		return nil, fmt.Errorf("cannot decode leaf certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse leaf certificate: %v", err)
	}

	return cert, nil
}

// VerifyCertificateChain verifies the certificate chain from leaf to root.
// It also checks that all certificate lifetimes are valid.
func VerifyCertificateChain(certificates PKICertificates) error {
	if isCertificateLifetimeValid(certificates.LeafCert) {
		return fmt.Errorf("leaf certificate is not valid")
	}

	if isCertificateLifetimeValid(certificates.IntermediateCert) {
		return fmt.Errorf("intermediate certificate is not valid")
	}
	interPool := x509.NewCertPool()
	interPool.AddCert(certificates.IntermediateCert)

	if isCertificateLifetimeValid(certificates.RootCert) {
		return fmt.Errorf("root certificate is not valid")
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(certificates.RootCert)

	_, err := certificates.LeafCert.Verify(x509.VerifyOptions{
		Intermediates: interPool,
		Roots:         rootPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})

	if err != nil {
		return fmt.Errorf("failed to verify certificate chain: %v", err)
	}

	return nil
}

func isCertificateLifetimeValid(certificate *x509.Certificate) bool {
	currentTime := time.Now()
	// check the current time is after the certificate NotBefore time
	if !currentTime.After(certificate.NotBefore) {
		return false
	}

	// check the current time is before the certificate NotAfter time
	if currentTime.Before(certificate.NotAfter) {
		return false
	}

	return true
}

// CompareCertificates compares two certificate fingerprints.
func CompareCertificates(cert1 x509.Certificate, cert2 x509.Certificate) error {
	fingerprint1 := sha256.Sum256(cert1.Raw)
	fingerprint2 := sha256.Sum256(cert2.Raw)
	if fingerprint1 != fingerprint2 {
		return fmt.Errorf("certificate fingerprint mismatch")
	}
	return nil
}

func getEKMHashFromConn(c *websocket.Conn) (string, error) {
	conn, ok := c.NetConn().(*tls.Conn)
	if !ok {
		return "", fmt.Errorf("failed to cast NetConn to *tls.Conn")
	}

	state := conn.ConnectionState()
	ekm, err := state.ExportKeyingMaterial("testing_nonce", nil, 32)
	if err != nil {
		return "", fmt.Errorf("failed to get EKM from TLS connection: %w", err)
	}

	sha := sha256.New()
	sha.Write(ekm)
	hash := base64.StdEncoding.EncodeToString(sha.Sum(nil))

	return hash, nil
}

func retrieveTokenAndEKMFromConn(conn *websocket.Conn) (string, string, error) {
	_, content, err := conn.ReadMessage()
	if err != nil {
		return "", "", fmt.Errorf("failed to read message from the connection: %v", err)
	}

	ekm, err := getEKMHashFromConn(conn)
	if err != nil {
		return "", "", fmt.Errorf("failed to get EKM from outbound request: %w", err)
	}

	return string(content), ekm, nil
}

// ValidateClaimsAgainstOPAPolicy validates the claims in the JWT token against the OPA policy.
func ValidateClaimsAgainstOPAPolicy(token jwt.Token, ekm string) error {
	data, err := os.ReadFile("opa_validation_values.json")
	authorized, err := EvaluateOPAPolicy(context.Background(), token, ekm, string(data))
	if err != nil {
		fmt.Println("Error evaluating OPA policy:", err)
		return fmt.Errorf("failed to evaluate OPA policy: %w", err)
	}
	if !authorized {
		fmt.Println("Remote TEE's JWT failed policy check.")
		return fmt.Errorf("remote TEE's JWT failed policy check")
	}
	fmt.Println("JWT is authorized.")
	return nil
}

// EvaluateOPAPolicy returns boolean indicating if OPA policy is satisfied or not, or error if occurred
func EvaluateOPAPolicy(ctx context.Context, token jwt.Token, ekm string, policyData string) (bool, error) {
	var claims jwt.MapClaims
	var ok bool
	if claims, ok = token.Claims.(jwt.MapClaims); !ok {
		return false, fmt.Errorf("failed to get the claims from the JWT")
	}

	module := fmt.Sprintf(opaPolicy, ekm)

	var json map[string]any
	err := util.UnmarshalJSON([]byte(policyData), &json)
	store := inmem.NewFromObject(json)

	// Bind 'allow' to the value of the policy decision
	// Bind 'hw_verified', 'image_verified', 'audience_verified, 'nonce_verified' to their respective policy evaluations
	query, err := rego.New(
		rego.Query("allow = data.confidential_space.allow; hw_verified = data.confidential_space.hw_verified; image__digest_verified = data.confidential_space.image_digest_verified; audience_verified = data.confidential_space.audience_verified; nonce_verified = data.confidential_space.nonce_verified; issuer_verified = data.confidential_space.issuer_verified; secboot_verified = data.confidential_space.secboot_verified; sw_name_verified = data.confidential_space.sw_name_verified"), // Argument 1 (Query string)
		rego.Store(store), // Argument 2 (Data store)
		rego.Module("confidential_space.rego", module), // Argument 3 (Policy module)
	).PrepareForEval(ctx)

	if err != nil {
		fmt.Printf("Error creating query: %v\n", err)
		return false, err
	}

	fmt.Println("Performing OPA query evaluation...")
	results, err := query.Eval(ctx, rego.EvalInput(claims))

	if err != nil {
		fmt.Printf("Error evaluating OPA policy: %v\n", err)
		return false, err
	} else if len(results) == 0 {
		fmt.Println("Undefined result from evaluating OPA policy")
		return false, err
	} else if result, ok := results[0].Bindings["allow"].(bool); !ok {
		fmt.Printf("Unexpected result type: %v\n", ok)
		fmt.Printf("Result: %+v\n", result)
		return false, err
	}

	fmt.Println("OPA policy evaluation completed.")

	fmt.Println("OPA policy result values:")
	for key, value := range results[0].Bindings {
		fmt.Printf("[ %s ]: %v\n", key, value)
	}
	result := results[0].Bindings["allow"]
	if result == true {
		fmt.Println("Policy check PASSED")
		return true, nil
	}
	fmt.Println("Policy check FAILED")
	return false, nil
}

func main() {
	fmt.Println("Initializing client...")

	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	dialer := websocket.Dialer{
		TLSClientConfig:  tlsconfig,
		HandshakeTimeout: 5 * time.Second,
	}

	ipAddress := os.Getenv(ipAddrEnvVar)
	url := fmt.Sprintf("wss://%s:8081/connection", ipAddress)

	fmt.Printf("Attempting to dial to url %v...\n", url)
	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		fmt.Printf("Failed to dial to url %s, err %v\n", url, err)
		return
	}

	defer conn.Close()

	tokenString, ekm, err := retrieveTokenAndEKMFromConn(conn)
	if err != nil {
		fmt.Printf("Failed to retrieve token and EKM from connection: %v\n", err)
		return
	}

	fmt.Printf("token: %v\n", tokenString)

	token, err := ValidatePKIToken(tokenString, ekm)
	if err != nil {
		fmt.Printf("Failed to validate PKI token, err: %v\n.", err)
		return
	}
	fmt.Println("PKI token validated successfully")

	err = ValidateClaimsAgainstOPAPolicy(token, ekm)
	if err != nil {
		fmt.Printf("Failed to validate claims against OPA policy: %v\n", err)
		return
	}

	fmt.Println("Validated token and claims. Sending sensitive data")

	data, err := readFile(mySensitiveDataFile)
	if err != nil {
		fmt.Printf("Failed to read data from the file: %v\n", err)
	}

	conn.WriteMessage(2, data)
	fmt.Println("Sent payload. Closing the connection")
	conn.Close()
}

EOF