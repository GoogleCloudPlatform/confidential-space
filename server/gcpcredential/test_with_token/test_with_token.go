package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/GoogleCloudPlatform/confidential-space/server/gcpcredential"
)

/*
This is a simple program to test a GCP-issued service token with the gcpcredential library.
Note the token is expected to have "http://www.example.com" as the audience.

To get a token:
$ curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=http://www.example.com&format=full" -H "Metadata-Flavor: Google"

Usage:
$ ./main [token]
*/

var audience = "http://www.example.com"

func getGoogleJWKs() (*gcpcredential.JWKS, error) {
	resp, err := http.Get("https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		return nil, fmt.Errorf("Unable to retrieve Google JWKs: %v", err)
	}

	jwks := &gcpcredential.JWKS{}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Unable to read response body: %v", err)
	}

	if err = json.Unmarshal(bodyBytes, jwks); err != nil {
		return nil, fmt.Errorf("Unable to unmarshal response: %v", err)
	}

	return jwks, nil
}

// A simple program that runs gcpcredentials.Validate on a provided token.
func main() {
	args := os.Args[1:]
	if len(args) != 1 {
		fmt.Printf("Unexpected number of arguments %v, expect 1\n", len(args))
		os.Exit(1)
	}

	fmt.Println("[1/2] Testing gcpcredential.Validate() ...")

	emails, err := gcpcredential.Validate(context.Background(), nil, args, audience)
	if err != nil {
		fmt.Printf("gcpcredential.Validate() failed: %v\n", err)
	} else {
		fmt.Printf("gcpcredential.Validate() succeeded: %v\n", emails)
	}

	fmt.Println("[2/2] Testing gcpcredential.ValidateWithJWKs() ...")

	// Get Google JWKs.
	fmt.Println("Retrieving JWKs ...")
	jwks, err := getGoogleJWKs()
	if err != nil {
		fmt.Printf("Error retrieving JWKs: %v\n", err)
		os.Exit(1)
	}

	emails, err = gcpcredential.ValidateWithJWKS(jwks, args, audience)
	if err != nil {
		fmt.Printf("gcpcredential.ValidateWithJWKS() failed: %v\n", err)
	} else {
		fmt.Printf("gcpcredential.ValidateWithJWKS() succeeded: %v\n", emails)
	}
}
