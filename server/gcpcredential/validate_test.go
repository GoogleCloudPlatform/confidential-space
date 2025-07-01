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
	"google3/third_party/golang/github_com/golang_jwt/jwt/v/v4/jwt"
	"google.golang.org/api/idtoken"
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

func TestValidation(t *testing.T) {
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

func TestValidateFailsWithInvalidToken(t *testing.T) {
	_, jwk := testRSASigner(t, testKeyID)
	jwks := &JWKS{[]JWK{jwk}}

	// Returns a hardcoded JWK for token validation.
	validatorClient := &http.Client{Transport: &jwkFetcher{jwkFetchFunc(t, jwks)}}

	// Validate.
	if _, err := Validate(context.Background(), validatorClient, []string{"fake.test.token"}, testAudience); err == nil {
		t.Errorf("Validate returned successfully, expected error")
	}

	// ValidateWithJWKS.
	if _, err := ValidateWithJWKS(jwks, []string{"fake.test.token"}, testAudience); err == nil {
		t.Errorf("ValidateWithJWKS returned successfully, expected error")
	}
}

func TestValidationOmitsBadToken(t *testing.T) {
	signer, jwk := testRSASigner(t, testKeyID)
	jwks := &JWKS{[]JWK{jwk}}

	// Returns a hardcoded JWK for token validation.
	validatorClient := &http.Client{Transport: &jwkFetcher{jwkFetchFunc(t, jwks)}}

	validEmail := "goodtoken@test.com"
	expectedEmails := []string{validEmail}
	validToken := testGCPCredential(t, &emailClaims{validEmail, true}, testAudience, testKeyID, signer)

	testcases := []struct {
		name      string
		badClaims *emailClaims
	}{
		{
			name:      "No email claim",
			badClaims: &emailClaims{EmailVerified: true},
		},
		{
			name:      "Email unverified",
			badClaims: &emailClaims{Email: "badtoken@test.com", EmailVerified: false},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Given a valid token and a "bad" token (ex. unverified email), expect to only return the former.
			badToken := testGCPCredential(t, tc.badClaims, testAudience, testKeyID, signer)

			testTokens := []string{validToken, badToken}

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
