package gcpcredential

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

	validator := func(token string) (map[string]any, error) {
		payload, err := v.Validate(ctx, token, expectedAudience)
		if err != nil {
			return nil, err
		}

		return payload.Claims, nil
	}

	return validateAndParse(credentials, validator)
}

type JWK struct {
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	E   string `json:"e"`
	N   string `json:"n"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type PublicKeys struct {
	Keys []JWK `json:"keys"`
}

func rsaPubKey(key JWK) (*rsa.PublicKey, error) {
	decodedN, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, err
	}
	decodedE, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(decodedN),
		E: int(new(big.Int).SetBytes(decodedE).Int64()),
	}, nil
}

func ecdsaPubKey(key JWK) (*ecdsa.PublicKey, error) {
	decodedX, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, err
	}
	decodedY, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(decodedX),
		Y:     new(big.Int).SetBytes(decodedY),
	}, nil
}

// Validates the provided credentials using the provided public keys.
// It is the caller's responsibility to retrieve and provide Google's JWKs (https://www.googleapis.com/oauth2/v3/certs).
// NOT TESTED YET - use at you own risk.
func ValidateWithPubKeysAndParse(jwks *PublicKeys, credentials []string, expectedAudience string) ([]string, error) {
	// For JWT validation - finds the JWK that corresponds to the tokens Key ID and parses it into its respective key type.
	keyFunc := func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"]
		if !ok {
			return nil, fmt.Errorf("token missing Key ID")
		}

		for _, k := range jwks.Keys {
			if kid == k.Kid {
				alg, ok := token.Header["alg"]
				if !ok {
					return nil, errors.New("no signing algorithm specified in token")
				}

				switch alg {
				case "RS256":
					return rsaPubKey(k)
				case "ES256":
					return ecdsaPubKey(k)
				default:
					return nil, fmt.Errorf("unsupported signing algorithm %v, expext RS256 or ES256", alg)
				}
			}
		}

		return nil, errors.New("no matching key found")
	}

	// Validates a Google-issued ID token per guidance at https://developers.google.com/identity/sign-in/web/backend-auth#verify-the-integrity-of-the-id-token.
	validator := func(token string) (map[string]any, error) {
		// Check the signature.
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(token, claims, keyFunc)
		if err != nil {
			return nil, err
		}

		// Check the audience.
		audience := claims["aud"]
		if audience != expectedAudience {
			return nil, fmt.Errorf("unexpected audience: %v, token %s", audience, token)
		}

		// Check the issuer.
		issuer := claims["iss"]
		if issuer != "accounts.google.com" && issuer != "https://accounts.google.com" {
			return nil, fmt.Errorf("invalid issuer: %v, token %s", issuer, token)
		}

		// Check the expiration.
		if time.Now().Unix() > claims["exp"].(int64) {
			return nil, errors.New("token is expired")
		}

		return claims, nil
	}

	return validateAndParse(credentials, validator)
}

type validationFunc func(token string) (map[string]any, error)

func validateAndParse(credentials []string, validator validationFunc) ([]string, error) {
	var emails []string
	for i, token := range credentials {
		claims, err := validator(token)
		if err != nil {
			return nil, fmt.Errorf("Error validating token in position %v: %v", i, err)
		}

		tokenClaims, err := parseEmailClaims(claims)
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

		emails = append(emails, tokenClaims.Email)
	}

	return emails, nil
}

// parse takes an idtoken.Payload, which stores claims in a map[string]any. We want to
// interpret the claims as a googleClaims struct. Instead of manually inspecting the map we just
// encode/decode via JSON.
// This is valid because the original claims were decoded from JSON (as part of the JWT).
// claims.go
func parseEmailClaims(mapClaims map[string]any) (*emailClaims, error) {
	data, err := json.Marshal(mapClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}
	claims := &emailClaims{}
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
type emailClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}
