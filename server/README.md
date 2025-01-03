### Verifier Server Utilities
The following module consists of utility libraries for Verifier Services
to use when validating Confidential Space attestations.

## `gcpcredential`
Validates Google-issued service account ID tokens, which is necessary to populate the `emails` claims in resulting tokens.

There are two methods for validation, described below. Both accept a list of tokens and output a list of the associated emails from each token.

### Validation with Google idtoken library
```golang
func Validate(ctx context.Context, client *http.Client, credentials []string, expectedAudience string) ([]string, error)
```

Simplest to call, this method uses the [`idtoken`](google.golang.org/api/idtoken) library to verify tokens.

#### Usage
```golang
emails, err := gcpcredential.Validate(context.Background(), nil, args, audience)
if err != nil {
	fmt.Printf("gcpcredential.Validate() failed: %v\n", err)
}
```
A custom HTTP client can be provided, which will be used to initialize the idtoken client. Otherwise, the method will create a default client that includes Google's CAs.

```golang
customClient := &http.Client{...}

emails, err := gcpcredential.Validate(context.Background(), customClient, tokens, audience)
if err != nil {
	fmt.Printf("gcpcredential.Validate() failed: %v\n", err)
}
```

Note this method can be costly as as each token verification requires at least one outgoing network call. If a custom HTTP client is not provided, there is an additional network call made to retrieve Google's CAs and initialize the default client. 

### Validation with Google Public Keys (Manual)
```golang
func ValidateWithJWKS(jwks *JWKS, credentials []string, expectedAudience string)
```
This method accepts JWKs as input and uses them to manually verify the tokens. This is suitable for callers who prefer to minimize the number of outgoing network calls made. The validation process itself makes no outgoing calls, but the caller is responsible for retrieving the appropriate JWKs for verification. See [here](https://developers.google.com/identity/sign-in/web/backend-auth#verify-the-integrity-of-the-id-token) for more information.

#### Usage
```golang
// Retrieve JWKs.
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

// Validate tokens.
emails, err = gcpcredential.ValidateWithJWKS(jwks, tokens, audience)
if err != nil {
	fmt.Printf("gcpcredential.ValidateWithJWKS() failed: %v\n", err)
}
```

### Testing
Both validation methods can be tested with the `test_with_token` binary. The program accepts one token as an argument, runs both validation methods against it and outputs the results to stdout.

```bash
$ cd gcpcredential/test_with_token
$ go build -o main .
$ ./main "$(curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=http://www.example.com&format=full" -H "Metadata-Flavor: Google")"
```


## `signedcontainer`
Validates container image signatures.

```golang
func Verify(imageDigest string, signatures []*ImageSignature) (*VerifyResult, error)
```

The `Verify` function accepts an image digest and list of signatures and outputs a `VerifyResult` object containing the following:
- `Verified` - containing information about the signatures that were successfully verified
- `Errors` - containing error information about the signatures that could not be verified.

Each element in `signatures` populates a value in either `Verified` or `Errors`. In other words, `len(signatures) == len(VerifyResult.Verified) + len(VerifyResult.Errors)`