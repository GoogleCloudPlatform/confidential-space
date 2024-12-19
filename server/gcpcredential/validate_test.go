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
func testSigningKey(t *testing.T) (*rsa.PrivateKey, jwkInfo) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating test key: %v", err)
	}

	jwk := jwkInfo{
		"alg": "RS256",
		"kid": testKeyID,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}

	return key, jwk
}

// Generates and returns a JWT token with the provided claims, audience, and signed by the provided key.
func testGCPCredential(t *testing.T, emailClaims *claims, aud string, signer *rsa.PrivateKey) string {
	t.Helper()

	now := time.Now().Unix()

	jwtClaims := jwt.MapClaims{
		"aud":            aud,
		"exp":            now + 60,
		"email":          emailClaims.Email,
		"email_verified": emailClaims.EmailVerified,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)
	token.Header = map[string]any{
		"kid": testKeyID,
		"alg": "RS256",
	}
	tokenString, err := token.SignedString(signer)
	if err != nil {
		t.Fatalf("Error generating token for %v: %v", emailClaims, err)
	}

	return tokenString
}

type jwkFetcher struct {
	jwkFunc func(req *http.Request) *http.Response
}

func (t *jwkFetcher) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.jwkFunc(req), nil
}

func testJWKFetcher(t *testing.T, jwks []jwkInfo) *jwkFetcher {
	t.Helper()
	return &jwkFetcher{
		jwkFunc: func(req *http.Request) *http.Response {
			jwks := map[string]any{
				"keys": jwks,
			}
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

func TestValidateAndParse(t *testing.T) {
	signer, jwk := testSigningKey(t)

	expectedEmails := []string{"token1@test.com", "token2@test.com"}
	testTokens := []string{
		testGCPCredential(t, &claims{expectedEmails[0], true}, testAudience, signer),
		testGCPCredential(t, &claims{expectedEmails[1], true}, testAudience, signer),
	}

	// Returns a hardcoded JWK for token validation.
	validatorClient := &http.Client{Transport: testJWKFetcher(t, []jwkInfo{jwk})}

	emails, err := ValidateAndParse(context.Background(), validatorClient, testTokens, testAudience)
	if err != nil {
		t.Fatalf("ValidateAndParse error %v", err)
	}

	if !cmp.Equal(emails, expectedEmails) {
		t.Errorf("ValidateAndParse did not return expected emails: got %v, want %v", emails, expectedEmails)
	}
}

func TestValidateAndParseValidationError(t *testing.T) {
	_, jwk := testSigningKey(t)

	// Returns a hardcoded JWK for token validation.
	validatorClient := &http.Client{Transport: testJWKFetcher(t, []jwkInfo{jwk})}

	if _, err := ValidateAndParse(context.Background(), validatorClient, []string{"fake.test.token"}, testAudience); err == nil {
		t.Errorf("ValidateAndParse returned successfully, expected error")
	}
}

func TestValidateAndParseOmitsBadToken(t *testing.T) {
	signer, jwk := testSigningKey(t)

	// Returns a hardcoded JWK for token validation.
	validatorClient := &http.Client{Transport: testJWKFetcher(t, []jwkInfo{jwk})}

	validEmail := "goodtoken@test.com"
	expectedEmails := []string{validEmail}
	validToken := testGCPCredential(t, &claims{validEmail, true}, testAudience, signer)

	testcases := []struct {
		name      string
		badClaims *claims
	}{
		{
			name:      "No email claim",
			badClaims: &claims{EmailVerified: true},
		},
		{
			name:      "Email unverified",
			badClaims: &claims{Email: "badtoken@test.com", EmailVerified: false},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			badToken := testGCPCredential(t, tc.badClaims, testAudience, signer)

			testTokens := []string{validToken, badToken}

			// Given a valid token and a "bad" token (ex. unverified email), expect to only return the former.
			emails, err := ValidateAndParse(context.Background(), validatorClient, testTokens, testAudience)
			if err != nil {
				t.Fatalf("ValidateAndParse error %v", err)
			}

			if !cmp.Equal(emails, expectedEmails) {
				t.Errorf("ValidateAndParse did not return expected emails: got %v, want %v", emails, expectedEmails)
			}
		})
	}
}

func TestParseClaims(t *testing.T) {
	expectedClaims := &claims{
		Email:         "test@googleserviceaccount.com",
		EmailVerified: true,
	}

	payload := &idtoken.Payload{
		Claims: map[string]any{
			"email":          expectedClaims.Email,
			"email_verified": expectedClaims.EmailVerified,
		},
	}

	claims, err := parseClaims(payload)
	if err != nil {
		t.Fatalf("parseClaims returned error %v", err)
	}

	if diff := cmp.Diff(claims, expectedClaims); diff != "" {
		t.Errorf("parseClaims(payload) = %v, want %v", claims, expectedClaims)
	}
}
