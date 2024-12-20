package gcpcredential

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"net/http"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/api/idtoken"
)

const testAudience = "testaud"
const testKeyID = "testkid"

func TestGoogleCACerts(t *testing.T) {
	if _, err := googleCACerts(); err != nil {
		t.Errorf("GoogleCACerts() returned error %v", nil)
	}
}

type jwkInfo = map[string]any

// Generates and returns an RSA256 private key and associated JWK.
func testSigningKey(t *testing.T) (*rsa.PrivateKey, JWK) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating test key: %v", err)
	}

	jwk := JWK{
		Alg: "RS256",
		Kid: testKeyID,
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}

	return key, jwk
}

// Generates and returns a JWT token with the provided claims, audience, and signed by the provided key.
func testGCPCredential(t *testing.T, claims *emailClaims, aud string, signer *rsa.PrivateKey) string {
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
		"kid": testKeyID,
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

func testJWKFetcher(t *testing.T, jwks *PublicKeys) *jwkFetcher {
	t.Helper()
	return &jwkFetcher{
		jwkFunc: func(req *http.Request) *http.Response {
			respBytes, err := json.Marshal(jwks)
			if err != nil {
				t.Fatalf("Unable to marshal server response: %v", err)
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       ioutil.NopCloser(bytes.NewBuffer(respBytes)),
			}
		},
	}
}

func TestValidation(t *testing.T) {
	signer, jwk := testSigningKey(t)
	jwks := &PublicKeys{[]JWK{jwk}}

	expectedEmails := []string{"token1@test.com", "token2@test.com"}
	testTokens := []string{
		testGCPCredential(t, &emailClaims{expectedEmails[0], true}, testAudience, signer),
		testGCPCredential(t, &emailClaims{expectedEmails[1], true}, testAudience, signer),
	}

	// Returns a hardcoded JWK for token validation.
	validatorClient := &http.Client{Transport: testJWKFetcher(t, jwks)}

	// ValidateAndParse.
	emails, err := ValidateAndParse(context.Background(), validatorClient, testTokens, testAudience)
	if err != nil {
		t.Fatalf("ValidateAndParse error %v", err)
	}

	if !cmp.Equal(emails, expectedEmails) {
		t.Errorf("ValidateAndParse did not return expected emails: got %v, want %v", emails, expectedEmails)
	}

	// ValidateAndParseWithPubkeys.
	emails, err = ValidateWithPubKeysAndParse(jwks, testTokens, testAudience)
	if err != nil {
		t.Fatalf("ValidateWithPubKeysAndParse error %v", err)
	}

	if !cmp.Equal(emails, expectedEmails) {
		t.Errorf("ValidateWithPubKeysAndParse did not return expected emails: got %v, want %v", emails, expectedEmails)
	}
}

func TestValidationError(t *testing.T) {
	_, jwk := testSigningKey(t)
	jwks := &PublicKeys{[]JWK{jwk}}

	// Returns a hardcoded JWK for token validation.
	validatorClient := &http.Client{Transport: testJWKFetcher(t, jwks)}

	// ValidateAndParse.
	if _, err := ValidateAndParse(context.Background(), validatorClient, []string{"fake.test.token"}, testAudience); err == nil {
		t.Errorf("ValidateAndParse returned successfully, expected error")
	}

	// ValidateAndParseWithPubkeys.
	if _, err := ValidateWithPubKeysAndParse(jwks, []string{"fake.test.token"}, testAudience); err == nil {
		t.Errorf("ValidateWithPubKeysAndParse returned successfully, expected error")
	}
}

func TestValidateAndParseOmitsBadToken(t *testing.T) {
	signer, jwk := testSigningKey(t)
	jwks := &PublicKeys{[]JWK{jwk}}

	// Returns a hardcoded JWK for token validation.
	validatorClient := &http.Client{Transport: testJWKFetcher(t, jwks)}

	validEmail := "goodtoken@test.com"
	expectedEmails := []string{validEmail}
	validToken := testGCPCredential(t, &emailClaims{validEmail, true}, testAudience, signer)

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
			badToken := testGCPCredential(t, tc.badClaims, testAudience, signer)

			testTokens := []string{validToken, badToken}

			// ValidateAndParse.
			emails, err := ValidateAndParse(context.Background(), validatorClient, testTokens, testAudience)
			if err != nil {
				t.Fatalf("ValidateAndParse error %v", err)
			}

			if !cmp.Equal(emails, expectedEmails) {
				t.Errorf("ValidateAndParse did not return expected emails: got %v, want %v", emails, expectedEmails)
			}

			// ValidateAndParseWithPubkeys.
			emails, err = ValidateWithPubKeysAndParse(jwks, testTokens, testAudience)
			if err != nil {
				t.Fatalf("ValidateWithPubKeysAndParse error %v", err)
			}

			if !cmp.Equal(emails, expectedEmails) {
				t.Errorf("ValidateWithPubKeysAndParse did not return expected emails: got %v, want %v", emails, expectedEmails)
			}

		})
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
