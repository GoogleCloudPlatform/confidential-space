package gcpcredential

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
)

//go:embed data/roots.pem
var googleCAPEM []byte

// The certificates are downloaded from https://pki.goog/faq/#faq-27.
// Note the guidance is to update at least semi-annually.
func googleCACerts() (*x509.CertPool, error) {
	certs := x509.NewCertPool()
	if !certs.AppendCertsFromPEM(googleCAPEM) {
		return nil, errors.New("failed to parse Google CA certificates")
	}

	return certs, nil
}

// ValidateAndParse validates each of the provided credentials, then returns the emails of the successfully verified tokens.
// If an http.Client is provided, it will be used to initialize the idtoken validation client.
func ValidateAndParse(ctx context.Context, client *http.Client, credentials []string, expectedAudience string) ([]string, error) {
	if client == nil {
		ca, err := googleCACerts()
		if err != nil {
			return nil, err
		}
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    ca,
					MinVersion: tls.VersionTLS13,
				},
			},
		}
	}

	validatorOptions := []idtoken.ClientOption{
		option.WithoutAuthentication(),
		option.WithHTTPClient(client),
	}

	v, err := idtoken.NewValidator(ctx, validatorOptions...)
	if err != nil {
		return nil, fmt.Errorf("could not create ID token validator: %v", err.Error())
	}

	var emailClaims []string

	for i, token := range credentials {
		payload, err := v.Validate(ctx, token, expectedAudience)
		if err != nil {
			return nil, fmt.Errorf("invalid ID token in position %v: %v, token %s", i, err.Error(), token)
		}

		tokenClaims, err := parseClaims(payload)
		if err != nil {
			fmt.Printf("Error with ID token in position %v: %v", i, err)
			continue
		}

		if tokenClaims.Email == "" {
			fmt.Printf("ID token in position %v has no email claim\n", i)
			continue
		}

		if !tokenClaims.EmailVerified {
			fmt.Printf("email claim for ID token in position %v is not verified\n", i)
			continue
		}

		emailClaims = append(emailClaims, tokenClaims.Email)
	}

	return emailClaims, nil
}

// parse takes an idtoken.Payload, which stores claims in a map[string]any. We want to
// interpret the claims as a googleClaims struct. Instead of manually inspecting the map we just
// encode/decode via JSON.
// This is valid because the original claims were decoded from JSON (as part of the JWT).
// claims.go
func parseClaims(payload *idtoken.Payload) (*claims, error) {
	data, err := json.Marshal(payload.Claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}
	claims := &claims{}
	if err = json.Unmarshal(data, claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}
	return claims, nil
}

// The subset of claims we care about in Google-issued OpenID tokens.
// Full claims documented at:
//
//		https://cloud.google.com/compute/docs/instances/verifying-instance-identity#payload
//		https://developers.google.com/identity/protocols/oauth2/openid-connect
type claims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}
