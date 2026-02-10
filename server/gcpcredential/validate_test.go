package gcpcredential

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
)

const testAudience = "testaud"
const testKeyID = "testkid"

type jwkInfo = map[string]any

// Generates and returns an RSA256 private key and associated JWK.
func testRSASigner(t *testing.T, keyID string) (*rsa.PrivateKey, JWK) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating test key: %v", err)
	}

	jwk := JWK{
		Alg: "RS256",
		Kid: keyID,
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}

	return key, jwk
}

// Generates and returns a JWT token with the provided claims, audience, and signed by the provided key.
func testGCPCredential(t *testing.T, claims *emailClaims, aud, keyID string, signer *rsa.PrivateKey) string {
	t.Helper()

	now := time.Now().Unix()

	jwtClaims := jwt.MapClaims{
		"aud":            aud,
		"iss":            "accounts.google.com",
		"exp":            now + 60,
		"email":          claims.Email,
		"email_verified": claims.EmailVerified,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)
	token.Header = map[string]any{
		"kid": keyID,
		"alg": "RS256",
	}
	tokenString, err := token.SignedString(signer)
	if err != nil {
		t.Fatalf("Error generating token for %v: %v", claims, err)
	}

	return tokenString
}

type jwkFetcher struct {
	jwkFunc func(req *http.Request) *http.Response
}

func (t *jwkFetcher) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.jwkFunc(req), nil
}

func jwkFetchFunc(t *testing.T, jwks *JWKS) func(req *http.Request) *http.Response {
	t.Helper()
	return func(req *http.Request) *http.Response {
		respBytes, err := json.Marshal(jwks)
		if err != nil {
			t.Fatalf("Unable to marshal server response: %v", err)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       ioutil.NopCloser(bytes.NewBuffer(respBytes)),
		}
	}
}

func TestValidateWithMultipleSigners(t *testing.T) {
	signerA, jwkA := testRSASigner(t, testKeyID+"A")
	signerB, jwkB := testRSASigner(t, testKeyID+"B")
	jwks := &JWKS{[]JWK{jwkA, jwkB}}

	expectedEmails := []string{"tokenA@test.com", "tokenB@test.com"}
	testTokens := []string{
		testGCPCredential(t, &emailClaims{expectedEmails[0], true}, testAudience, testKeyID+"A", signerA),
		testGCPCredential(t, &emailClaims{expectedEmails[1], true}, testAudience, testKeyID+"B", signerB),
	}

	// Returns a hardcoded JWK for token validation.
	validatorClient := &http.Client{Transport: &jwkFetcher{jwkFetchFunc(t, jwks)}}

	// Validate.
	emails, err := Validate(t.Context(), validatorClient, testTokens, testAudience)
	if err != nil {
		t.Fatalf("Validate error %v", err)
	}

	if !cmp.Equal(emails, expectedEmails) {
		t.Errorf("Validate did not return expected emails: got %v, want %v", emails, expectedEmails)
	}

	// ValidateWithJWKS.
	emails, err = ValidateWithJWKS(jwks, testTokens, testAudience)
	if err != nil {
		t.Fatalf("ValidateWithJWKS error %v", err)
	}

	if !cmp.Equal(emails, expectedEmails) {
		t.Errorf("ValidateWithJWKS did not return expected emails: got %v, want %v", emails, expectedEmails)
	}
}

func TestValidateFailsWithInvalidToken(t *testing.T) {
	_, jwk := testRSASigner(t, testKeyID)
	jwks := &JWKS{[]JWK{jwk}}

	// Returns a hardcoded JWK for token validation.
	validatorClient := &http.Client{Transport: &jwkFetcher{jwkFetchFunc(t, jwks)}}

	// Validate.
	if _, err := Validate(t.Context(), validatorClient, []string{"fake.test.token"}, testAudience); err == nil {
		t.Errorf("Validate returned successfully, expected error")
	}

	// ValidateWithJWKS.
	if _, err := ValidateWithJWKS(jwks, []string{"fake.test.token"}, testAudience); err == nil {
		t.Errorf("ValidateWithJWKS returned successfully, expected error")
	}
}

func TestValidation(t *testing.T) {
	signer, jwk := testRSASigner(t, testKeyID)
	jwks := &JWKS{[]JWK{jwk}}

	// Returns a hardcoded JWK for token validation.
	validatorClient := &http.Client{Transport: &jwkFetcher{jwkFetchFunc(t, jwks)}}

	testcases := []struct {
		name           string
		tokenClaims    []*emailClaims
		expectedEmails []string
	}{
		{
			name: "Valid tokens",
			tokenClaims: []*emailClaims{
				&emailClaims{Email: "goodtoken@test.com", EmailVerified: true},
				&emailClaims{Email: "alsoagoodtoken@test.com", EmailVerified: true},
			},
			expectedEmails: []string{"goodtoken@test.com", "alsoagoodtoken@test.com"},
		},
		{
			name: "No email claim",
			tokenClaims: []*emailClaims{
				&emailClaims{Email: "goodtoken@test.com", EmailVerified: true},
				&emailClaims{Email: "", EmailVerified: true},
			},
			expectedEmails: []string{"goodtoken@test.com"},
		},
		{
			name: "Email unverified",
			tokenClaims: []*emailClaims{
				&emailClaims{Email: "goodtoken@test.com", EmailVerified: true},
				&emailClaims{Email: "badtoken@test.com", EmailVerified: false},
			},
			expectedEmails: []string{"goodtoken@test.com"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tokens := make([]string, len(tc.tokenClaims))
			for i, claims := range tc.tokenClaims {
				tokens[i] = testGCPCredential(t, claims, testAudience, testKeyID, signer)
			}

			// Validate.
			emails, err := Validate(t.Context(), validatorClient, tokens, testAudience)
			if err != nil {
				t.Fatalf("Validate error %v", err)
			}

			if !cmp.Equal(emails, tc.expectedEmails) {
				t.Errorf("Validate did not return expected emails: got %v, want %v", emails, tc.expectedEmails)
			}

			// ValidateWithJWKS.
			emails, err = ValidateWithJWKS(jwks, tokens, testAudience)
			if err != nil {
				t.Fatalf("ValidateWithJWKS error %v", err)
			}

			if !cmp.Equal(emails, tc.expectedEmails) {
				t.Errorf("ValidateWithJWKS did not return expected emails: got %v, want %v", emails, tc.expectedEmails)
			}

		})
	}
}

func TestValidateWithECDSASigner(t *testing.T) {
	// Create ECDSA signing key and JWK.
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Error generating ECDSA signing key: %v", err)
	}

	jwks := &JWKS{[]JWK{
		{
			Alg: "ES256",
			Kid: testKeyID,
			X:   base64.RawURLEncoding.EncodeToString(signer.X.Bytes()),
			Y:   base64.RawURLEncoding.EncodeToString(signer.Y.Bytes()),
		},
	}}

	// Create ECDSA-signed token.
	expectedEmails := []string{"tokenA@test.com"}

	jwtClaims := jwt.MapClaims{
		"aud":            testAudience,
		"iss":            "accounts.google.com",
		"exp":            time.Now().Unix() + 60,
		"email":          expectedEmails[0],
		"email_verified": true,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwtClaims)
	token.Header = map[string]any{
		"kid": testKeyID,
		"alg": "ES256",
	}

	tokenString, err := token.SignedString(signer)
	if err != nil {
		t.Fatalf("Error generating token: %v", err)
	}

	testTokens := []string{tokenString}

	// Returns a hardcoded JWK for token validation.
	validatorClient := &http.Client{Transport: &jwkFetcher{jwkFetchFunc(t, jwks)}}

	// Validate.
	emails, err := Validate(context.Background(), validatorClient, testTokens, testAudience)
	if err != nil {
		t.Fatalf("Validate error %v", err)
	}

	if !cmp.Equal(emails, expectedEmails) {
		t.Errorf("Validate did not return expected emails: got %v, want %v", emails, expectedEmails)
	}

	// ValidateWithJWKS.
	emails, err = ValidateWithJWKS(jwks, testTokens, testAudience)
	if err != nil {
		t.Fatalf("ValidateWithJWKS error %v", err)
	}

	if !cmp.Equal(emails, expectedEmails) {
		t.Errorf("ValidateWithJWKS did not return expected emails: got %v, want %v", emails, expectedEmails)
	}
}

func TestValidateWithOptions(t *testing.T) {
	signerA, jwkA := testRSASigner(t, testKeyID+"A")
	signerB, jwkB := testRSASigner(t, testKeyID+"B")
	jwks := &JWKS{[]JWK{jwkA, jwkB}}

	expectedEmails := []string{"tokenA@test.com", "tokenB@test.com"}
	testTokens := []string{
		testGCPCredential(t, &emailClaims{expectedEmails[0], true}, testAudience, testKeyID+"A", signerA),
		testGCPCredential(t, &emailClaims{expectedEmails[1], true}, testAudience, testKeyID+"B", signerB),
	}

	// Returns a hardcoded JWK for token validation.
	validatorClient := &http.Client{Transport: &jwkFetcher{jwkFetchFunc(t, jwks)}}
	validatorOpts := []idtoken.ClientOption{
		option.WithoutAuthentication(),
		option.WithHTTPClient(validatorClient),
	}

	got, err := ValidateWithOptions(t.Context(), testTokens, testAudience, validatorOpts)
	if err != nil {
		t.Errorf("ValidateWithOptions(%v, %q, %v) returned an unexpected error: %v", testTokens, testAudience, validatorOpts, err)
	}

	if diff := cmp.Diff(expectedEmails, got); diff != "" {
		t.Errorf("ValidateWithOptions(%v, %q, %v) returned an unexpected diff (-want +got): %v", testTokens, testAudience, validatorOpts, diff)
	}
}

func TestParseClaims(t *testing.T) {
	expectedClaims := &emailClaims{
		Email:         "test@googleserviceaccount.com",
		EmailVerified: true,
	}

	payload := &idtoken.Payload{
		Claims: map[string]any{
			"email":          expectedClaims.Email,
			"email_verified": expectedClaims.EmailVerified,
		},
	}

	claims, err := parseEmailClaims(payload.Claims)
	if err != nil {
		t.Fatalf("parseClaims returned error %v", err)
	}

	if diff := cmp.Diff(claims, expectedClaims); diff != "" {
		t.Errorf("parseClaims(payload) = %v, want %v", claims, expectedClaims)
	}
}
