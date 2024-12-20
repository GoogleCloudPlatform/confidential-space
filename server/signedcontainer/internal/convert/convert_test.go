package convert

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
	tinkecdsa "github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapss"
)

// Generate a RSA public key by following these steps:
// 1. Generate a RSA private key using:
// openssl genrsa -out rsa_private.pem 2048
// 2. Extract a public key from the private key using:
// openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
//
// It uses OID 1.2.840.113549.1.1.1 "rsaEncryption"
const rsaPubKeyPKIX = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtXmc2Ir66Wq0D2eO6+fK
I7SKJ85N6/FTsBW+i/KHQaecmpAmaatqqoSzmQ+34Ibpe6UPH+MlI19cwEYP/8Vk
MbMII9mM460jdLPUvhigJthv5nHm1htN+WPG9BiQuDkktWhOdJgZFbWtHXCEMW38
zZH6FDsnvuTW9oPDjEKNB7CpWnpbZNx50pTb2mMQZBW75W0mYuw4h++fo5Z7EpWm
N8Fg2TK/2Qu4KUSSdu8yYiZTn97AMNjoAiNFjRwWw7G+O2rOcMhuU2Gt8eieXyFm
JI6E7jgZRHtW6VddCLbchgJAXtbNOkV5cG2GLyoXq6sVJ61F70tx5VB54665SgNU
JwIDAQAB
-----END PUBLIC KEY-----`

const rsaPubKeyPKCS1 = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAtXmc2Ir66Wq0D2eO6+fKI7SKJ85N6/FTsBW+i/KHQaecmpAmaatq
qoSzmQ+34Ibpe6UPH+MlI19cwEYP/8VkMbMII9mM460jdLPUvhigJthv5nHm1htN
+WPG9BiQuDkktWhOdJgZFbWtHXCEMW38zZH6FDsnvuTW9oPDjEKNB7CpWnpbZNx5
0pTb2mMQZBW75W0mYuw4h++fo5Z7EpWmN8Fg2TK/2Qu4KUSSdu8yYiZTn97AMNjo
AiNFjRwWw7G+O2rOcMhuU2Gt8eieXyFmJI6E7jgZRHtW6VddCLbchgJAXtbNOkV5
cG2GLyoXq6sVJ61F70tx5VB54665SgNUJwIDAQAB
-----END RSA PUBLIC KEY-----`

// Generate a ECDSA public key by following these steps:
// 1. Generate a ECDSA private key using:
// openssl ecparam -name prime256v1 -genkey -noout -out ec_private.pem
// 2. Extract a public key from the private key using:
// openssl ec -in private.pem -pubout -out ec_public.pem
const ecdsaPubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMLdxI5u7ON+1QzJ+njeahioIRU/V
gqLf36SUAhbJ/Qnof5HkiJfXB/cBawuddv9JfNFL4nXLNZTHfz4uBrPduw==
-----END PUBLIC KEY-----
`

func TestUnmarshalPEMToPublicKey(t *testing.T) {
	testCases := []struct {
		name     string
		pemBytes []byte
		wantPass bool
	}{
		{name: "Unmarshal PKIX public key success", pemBytes: []byte(rsaPubKeyPKIX), wantPass: true},
		{name: "Unmarshal PKCS1 public key success", pemBytes: []byte(rsaPubKeyPKCS1), wantPass: true},
		{name: "Unmarshal invalid public key failed", pemBytes: []byte("invalid public key"), wantPass: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := unmarshalPEMToPublicKey(tc.pemBytes)
			if got, want := err == nil, tc.wantPass; got != want {
				t.Errorf("UnmarshalPEMToPubKey() = %v, but want: %v", got, want)
			}
		})
	}
}

func TestPemToECDSAP256Sha256KeysetHandle(t *testing.T) {
	publicKey, err := unmarshalPEMToPublicKey([]byte(ecdsaPubKey))
	if err != nil {
		t.Fatalf("UnmarshalPEMToPublicKey(%v) err = %v, want nil", ecdsaPubKey, err)
	}
	ecdhPublicKey, err := publicKey.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		t.Fatalf("publicKey.(*ecdsa.PublicKey).ECDH() err = %v, want nil", err)
	}
	params, err := tinkecdsa.NewParameters(tinkecdsa.NistP256, tinkecdsa.SHA256, tinkecdsa.DER, tinkecdsa.VariantNoPrefix)
	if err != nil {
		t.Fatalf("tinkecdsa.NewParameters(%v, %v, %v, %v) err = %v, want nil", tinkecdsa.NistP256, tinkecdsa.SHA256, tinkecdsa.DER, tinkecdsa.VariantNoPrefix, err)
	}
	tinkPublicKey, err := tinkecdsa.NewPublicKey(ecdhPublicKey.Bytes(), 0, params)
	if err != nil {
		t.Fatalf("tinkecdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", ecdhPublicKey.Bytes(), 0, params, err)
	}

	gotHandle, err := PemToECDSAP256Sha256WithDEREncodingKeysetHandle([]byte(ecdsaPubKey))
	if err != nil {
		t.Fatalf("PemToECDSAP256Sha256WithDEREncodingKeysetHandle(%v) err = %v, want nil", ecdsaPubKey, err)
	}
	if gotHandle.Len() != 1 {
		t.Fatalf("gotHandle.Len() = %v, want 1", gotHandle.Len())
	}
	gotEntry, err := gotHandle.Entry(0)
	if err != nil {
		t.Fatalf("gotHandle.Entry(0) err = %v, want nil", err)
	}
	if gotEntry.KeyStatus() != keyset.Enabled {
		t.Errorf("gotEntry.KeyStatus() = %v, want %v", gotEntry.KeyStatus(), keyset.Enabled)
	}
	if !gotEntry.IsPrimary() {
		t.Errorf("gotEntry.IsPrimary() = false, want true")
	}
	if !gotEntry.Key().Equal(tinkPublicKey) {
		t.Errorf("gotEntry.Key().Equal(tinkPublicKey) = false, want true")
	}
}

func TestPemToRsaSsaPkcs1Sha256Keyset(t *testing.T) {
	publicKey, err := unmarshalPEMToPublicKey([]byte(rsaPubKeyPKCS1))
	if err != nil {
		t.Fatalf("UnmarshalPEMToPublicKey() failed: %v", err)
	}
	rsaSSAPKCS1PublicKey := publicKey.(*rsa.PublicKey)
	params, err := rsassapkcs1.NewParameters(rsaSSAPKCS1PublicKey.N.BitLen(), rsassapkcs1.SHA256, f4, rsassapkcs1.VariantNoPrefix)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) err = %v, want nil", rsaSSAPKCS1PublicKey.N.BitLen(), rsassapkcs1.SHA256, f4, rsassapkcs1.VariantNoPrefix, err)
	}
	tinkPublicKey, err := rsassapkcs1.NewPublicKey(rsaSSAPKCS1PublicKey.N.Bytes(), 0, params)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewPublicKey(%v, %v, %v) err = %v, want nil", rsaSSAPKCS1PublicKey.N.Bytes(), 0, params, err)
	}
	gotHandle, err := PemToRsaSsaPkcs1Sha256KeysetHandle([]byte(rsaPubKeyPKCS1))
	if err != nil {
		t.Fatalf("PemToRsaSsaPkcs1Sha256Keyset() failed: %v", err)
	}
	if gotHandle.Len() != 1 {
		t.Fatalf("gotHandle.Len() = %v, want 1", gotHandle.Len())
	}
	gotEntry, err := gotHandle.Entry(0)
	if err != nil {
		t.Fatalf("gotHandle.Entry(0) err = %v, want nil", err)
	}
	if gotEntry.KeyStatus() != keyset.Enabled {
		t.Errorf("gotEntry.KeyStatus() = %v, want %v", gotEntry.KeyStatus(), keyset.Enabled)
	}
	if !gotEntry.IsPrimary() {
		t.Errorf("gotEntry.IsPrimary() = false, want true")
	}
	if !gotEntry.Key().Equal(tinkPublicKey) {
		t.Errorf("gotEntry.Key().Equal(tinkPublicKey) = false, want true")
	}
}

func TestPemToRsaSsaPssSha256KeysetHandle(t *testing.T) {
	publicKey, err := unmarshalPEMToPublicKey([]byte(rsaPubKeyPKIX))
	if err != nil {
		t.Fatalf("UnmarshalPEMToPublicKey() failed: %v", err)
	}
	rsaSSAPSSPublicKey := publicKey.(*rsa.PublicKey)
	paramValues := rsassapss.ParametersValues{
		ModulusSizeBits: rsaSSAPSSPublicKey.N.BitLen(),
		SigHashType:     rsassapss.SHA256,
		MGF1HashType:    rsassapss.SHA256,
		PublicExponent:  rsaSSAPSSPublicKey.E,
		SaltLengthBytes: rsa.PSSSaltLengthAuto,
	}
	params, err := rsassapss.NewParameters(paramValues, rsassapss.VariantNoPrefix)
	if err != nil {
		t.Fatalf("rsassapss.NewParameters(%v, %v) err = %v, want nil", paramValues, rsassapss.VariantNoPrefix, err)
	}
	tinkPublicKey, err := rsassapss.NewPublicKey(rsaSSAPSSPublicKey.N.Bytes(), 0, params)
	if err != nil {
		t.Fatalf("rsassapss.NewPublicKey(%v, %v, %v) err = %v, want nil", rsaSSAPSSPublicKey.N.Bytes(), 0, params, err)
	}
	gotHandle, err := PemToRsaSsaPssSha256KeysetHandle([]byte(rsaPubKeyPKIX))
	if err != nil {
		t.Fatalf("PemToRsaSsaPssSha256Keyset() failed: %v", err)
	}
	if gotHandle.Len() != 1 {
		t.Fatalf("gotHandle.Len() = %v, want 1", gotHandle.Len())
	}
	gotEntry, err := gotHandle.Entry(0)
	if err != nil {
		t.Fatalf("gotHandle.Entry(0) err = %v, want nil", err)
	}
	if gotEntry.KeyStatus() != keyset.Enabled {
		t.Errorf("gotEntry.KeyStatus() = %v, want %v", gotEntry.KeyStatus(), keyset.Enabled)
	}
	if !gotEntry.IsPrimary() {
		t.Errorf("gotEntry.IsPrimary() = false, want true")
	}
	if !gotEntry.Key().Equal(tinkPublicKey) {
		t.Errorf("gotEntry.Key().Equal(tinkPublicKey) = false, want true")
	}
}

func TestPemToECDSAP256Sha256WithDEREncodingKeysetHandleVerify(t *testing.T) {
	// base64-encoded signature over a byte slice of "hello world!":
	// openssl dgst -sign ec_private.pem -sha256 | base64
	base64Sig := "MEYCIQDl0nmdnkMBZc5rLmMR3cWOcZbXcBiNyCdhctKN+RpqHAIhALiaSW8gdCiBjxmXNWF8BBKAVu24u9JisY6juSfYbcNF"
	sig, err := base64.StdEncoding.DecodeString(base64Sig)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("hello world!")
	handle, err := PemToECDSAP256Sha256WithDEREncodingKeysetHandle([]byte(ecdsaPubKey))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.NewVerifier(handle)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(sig, data); err != nil {
		t.Errorf("verifier.Verify(sig, data) err = %q, want nil", err)
	}
}

func TestPemToRsaSsaPkcs1Sha256KeysetHandleVerify(t *testing.T) {
	// base64-encoded signature over a byte slice of "hello world!":
	// openssl dgst -sign rsa_private.pem -sha256 | base64
	base64Sig := "RnQyBe1pPWCvfRS5yf8eljt6Jd+d7GucmdQSbGqlhySyI/OWBQXxMofX5Q4sJqbxOh/FSxhgEddBSCcM+oVWOmg+Gtn15kxaNX4p3o2TgZdIf9WN29pjbhe7Im5TxB5ZKOwfc/2/dVy15Hr8sQVT/arbJQzHaphQInQxkv2BHn8kiuTccE8FB2jJKfwXsYn+/ibRNB6X4AuhoiGZzg0+RxqxWTFVii0bkRwSFJmkTkoZlxVBZRsVwCMDSMbE3AIO+We1iOk+VUHfaxbgcmEzlA84NX01sXDrlMXkHzwt1iE9wCJZWk9B+JpB2DquVVb9Zsg59O7xzFTeWjaNQUN9sw=="
	sig, err := base64.StdEncoding.DecodeString(base64Sig)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("hello world!")
	handle, err := PemToRsaSsaPkcs1Sha256KeysetHandle([]byte(rsaPubKeyPKIX))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.NewVerifier(handle)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(sig, data); err != nil {
		t.Errorf("verifier.Verify(sig, data) err = %q, want nil", err)
	}
}

func TestPemToRsaSsaPssSha256KeysetHandleVerify(t *testing.T) {
	// base64-encoded signature over a byte slice of "hello world!":
	// openssl dgst -sign rsa_private.pem -sigopt rsa_padding_mode:pss -sha256 | base64
	base64Sig := "ZDXvvjpd41q9P0UFH76g8TgedfbczT9/XAg38bPmnSPS3gzq6ptG/uscqYpXfXBzZV4kkdoz8ksSPbaFgMl1jaldcetNJvnpnJbgeO5aFxzCYAg+y5rgLgeOswfDZ+TeW6D8zKB+yxGIu6q30enq3CQ7Bh3B1zZ1m1wgNkr0AbSKxpbYolYMEWFjPcnrk3KG7L2x/H17mmVoLNeP8XMBEjrI6jpWx7TPo2xqZsfQ0vDw8EwV3WXE2QSTiRkqwydKrNvYTjyCYpE4Clep92f4/6+JZGjHBN/aYcRi8mKU9ZqVKO410NuqoCkZTgyIg0AJnxKYLtTwqXrW013xV/dhBQ=="
	sig, err := base64.StdEncoding.DecodeString(base64Sig)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("hello world!")
	handle, err := PemToRsaSsaPssSha256KeysetHandle([]byte(rsaPubKeyPKIX))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.NewVerifier(handle)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(sig, data); err != nil {
		t.Errorf("verifier.Verify(sig, data) err = %q, want nil", err)
	}
}

func TestCreateSignExportAsPemImportVerify(t *testing.T) {
	// Create private and public keyset with one ECDSA key.
	// This template uses SHA256, is over curve NIST P-256, uses
	// DER signature encoding and does not add an output prefix.
	template := signature.ECDSAP256KeyWithoutPrefixTemplate()
	privateHandle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle(template) err = %v, want nil", err)
	}
	publicHandle, err := privateHandle.Public()
	if err != nil {
		t.Fatalf("privateHandle.Public() err = %v, want nil", err)
	}

	// Use private keyset to sign some data.
	signer, err := signature.NewSigner(privateHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner(privateHandle) err = %v, want nil", err)
	}
	data := []byte("hello world!")
	sign, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("signer.Sign(data) err = %v, want nil", err)
	}

	// Export pem-encoded public key
	pemEcdsaPublicKey, err := PemFromECDSAP256Sha256WithDEREncodingKeysetHandle(publicHandle)
	if err != nil {
		t.Fatalf("PemFromECDSAP256Sha256WithDEREncodingKeysetHandle(handle) err = %v, want nil", err)
	}

	// Import public key and verify signature
	importedHandle, err := PemToECDSAP256Sha256WithDEREncodingKeysetHandle(pemEcdsaPublicKey)
	if err != nil {
		t.Fatalf("PemToECDSAP256Sha256WithDEREncodingKeysetHandle(pemEcdsaPublicKey) err = %v, want nil", err)
	}
	verifier, err := signature.NewVerifier(importedHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier(importedHandle) err = %v, want nil", err)
	}
	if err := verifier.Verify(sign, data); err != nil {
		t.Errorf("verifier.Verify(sign, data) err = %q, want nil", err)
	}
}

func TestPemFromECDSAP256Sha256KeysetHandle_isInverseOfPemToECDSAP256Sha256WithDEREncodingKeysetHandle(t *testing.T) {
	handle, err := PemToECDSAP256Sha256WithDEREncodingKeysetHandle([]byte(ecdsaPubKey))
	if err != nil {
		t.Fatal(err)
	}

	pemEncoded, err := PemFromECDSAP256Sha256WithDEREncodingKeysetHandle(handle)
	if err != nil {
		t.Fatal(err)
	}

	if got := string(pemEncoded); got != ecdsaPubKey {
		t.Fatalf("got pemEncoded = %s, want %s", got, ecdsaPubKey)
	}
}

func TestPemFromECDSAP256Sha256KeysetHandleWithPrivateKey(t *testing.T) {
	template := signature.ECDSAP256KeyWithoutPrefixTemplate()
	privHandle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatal(err)
	}
	_, err = PemFromECDSAP256Sha256WithDEREncodingKeysetHandle(privHandle)
	if err == nil {
		t.Error("PemFromECDSAP256Sha256WithDEREncodingKeysetHandle(privHandle) err = nil, want error")
	}
}

func TestPemToECDSAP256Sha256KeysetHandleFailsWithUnsupportedEncoding(t *testing.T) {
	template := signature.ECDSAP256RawKeyTemplate() // This template uses IEEE_P1363 encoding
	privHandle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := privHandle.Public()
	if err != nil {
		t.Fatal(err)
	}
	_, err = PemFromECDSAP256Sha256WithDEREncodingKeysetHandle(handle)
	if err == nil {
		t.Error("PemFromECDSAP256Sha256WithDEREncodingKeysetHandle(handle) err = nil, want error")
	}
}

func TestPemToECDSAP256Sha256KeysetHandleFailsWithUnsupportedCurve(t *testing.T) {
	template := signature.ECDSAP384SHA384KeyWithoutPrefixTemplate()
	privHandle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := privHandle.Public()
	if err != nil {
		t.Fatal(err)
	}
	_, err = PemFromECDSAP256Sha256WithDEREncodingKeysetHandle(handle)
	if err == nil {
		t.Error("PemFromECDSAP256Sha256WithDEREncodingKeysetHandle(handle) err = nil, want error")
	}
}

func TestPemToECDSAP256Sha256KeysetHandleFailsWithTinkOutputPrefix(t *testing.T) {
	template := signature.ECDSAP256KeyTemplate()
	privHandle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := privHandle.Public()
	if err != nil {
		t.Fatal(err)
	}
	_, err = PemFromECDSAP256Sha256WithDEREncodingKeysetHandle(handle)
	if err == nil {
		t.Error("PemFromECDSAP256Sha256WithDEREncodingKeysetHandle(handle) err = nil, want error")
	}
}

func TestPemToRsaSsaPkcs1Sha256KeysetHandle_notSupported(t *testing.T) {
	// RSA public key with OID 1.2.840.113549.1.1.11 "sha256WithRSAEncryption"
	// from RFC 4055.
	//
	// Copied from tink-java's PemKeyConverterTest.java.
	const rsaPubKeySha256 = `-----BEGIN PUBLIC KEY-----
	MIIBojANBgkqhkiG9w0BAQsFAAOCAY8AMIIBigKCAYEAoHiH83M3gZawt0jN8xwU
	c1zPoPEXrK/aoh/eS251WTkLg057kunhzJ1J/A/mz7YEKWUrS/mndo9x/EJxym/v
	TkMRkuvcmGML+5TFuvGLTPeIHYRIPkxEwi2xWpYncFoLQqJtbz1gCa7g0qcb7fTU
	sO5rb+wvFuEnfsqjve26QGRzpHbRaI3w+tHaeVUmx+ZBmBtIErBbaS1gxgsr+kJM
	i2IPQNydulnixxDn7nULPhNMH3H0MhBoiv8XqqQc21ZodT8ABrHPlRvFlR9NiaMR
	lphepVwJZsNmK8/k5M008S5K/X5cShMHObEBfWpYOIL9ctsaZ0GHAsiwE1PM91t7
	k/rsDgvjYhHV8r2RDhVSMjcRu+tzhY+JnMHsBj72fYjgxpnVponFIQbwbpYPCdKj
	z4T1O76ipHPt8ubgF2gB0/ocLTWOHlom9kask3luwfrcaZHA7BnJ3ZCyWi3Tv3PS
	zx7qiGf5bKpaLfVJc6yyotoKE2fsdK+7lo9Rd2UjjRdpAgMBAAE=
	-----END PUBLIC KEY-----`

	// RSA SSA PSS public key with OID 1.2.840.113549.1.1.10 "id_RSASSA_PSS" from
	// RFC 4055. It has parameters sig hash and mgf1 hash set to SHA256.
	//
	// Copied from tink-java's PemKeyConverterTest.java.
	const rsaSsaPssPublicKey = `-----BEGIN PUBLIC KEY-----
	MIIBUDA7BgkqhkiG9w0BAQowLjANBglghkgBZQMEAgEFADAaBgkqhkiG9w0BAQgw
	DQYJYIZIAWUDBAIBBQACARQDggEPADCCAQoCggEBALE8O9Jpvv6rBFCOeVIXdsA4
	6LhO8xfQBMCjt9Bh5H/bc30jJkGMlDaKsgmzOh8IsFVGx2rBJrlXyOhkpNM1jAiY
	ZC46/+YXzpepQMoWjQsSK+3/GM0U8RDZcLK2DqZb2Kd3LM/E8qK8gbz7hu+OHnc1
	UEst8JT97peDAW5TEk9EmEf2HY19Ok8OQCDzMINVWfBf5HuxgjbQMmOnU+TU3h1e
	Z2axdGbbAzdIPEs8UXs/Eht6z+GlkRI9V23PuNajKl1IIJ3YivzJWX/fCzH6fDhE
	/AhacWV+3bEqUG7McXbu4Qh5Me95YvGigJgAMqpF3gU3xTtltj1G70Le4QSbZ08C
	AwEAAQ==
	-----END PUBLIC KEY-----`

	testCases := []struct {
		name     string
		pemBytes []byte
	}{
		{name: "RSA PEM public key with OID sha256WithRSAEncryption", pemBytes: []byte(rsaPubKeySha256)},
		{name: "RSA PEM public key with id_RSASSA_PSS", pemBytes: []byte(rsaSsaPssPublicKey)},
		{name: "invalid", pemBytes: []byte("invalid public key")},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PemToRsaSsaPkcs1Sha256KeysetHandle(tc.pemBytes)
			if err == nil {
				t.Error("UnmarshalPEMToPubKey() err = nil, but want error")
			}
		})
	}
}

func TestPemFromECDSAP256Sha256KeysetHandle_failsForRsaSsaPkcs1PublicKey(t *testing.T) {
	handle, err := PemToRsaSsaPkcs1Sha256KeysetHandle([]byte(rsaPubKeyPKIX))
	if err != nil {
		t.Fatal(err)
	}
	_, err = PemFromECDSAP256Sha256WithDEREncodingKeysetHandle(handle)
	if err == nil {
		t.Error("PemFromECDSAP256Sha256WithDEREncodingKeysetHandle(handle) err = nil, want error")
	}
}

func TestCreateRsaSignExportAsPemImportVerify(t *testing.T) {
	// Create private and public keyset with one RSA key.
	template := signature.RSA_SSA_PKCS1_3072_SHA256_F4_RAW_Key_Template()
	privateHandle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle(template) err = %v, want nil", err)
	}
	publicHandle, err := privateHandle.Public()
	if err != nil {
		t.Fatalf("privateHandle.Public() err = %v, want nil", err)
	}

	// Use private keyset to sign some data.
	signer, err := signature.NewSigner(privateHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner(privateHandle) err = %v, want nil", err)
	}
	data := []byte("hello world!")
	sign, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("signer.Sign(data) err = %v, want nil", err)
	}

	// Export pem-encoded public key
	pemRsaPublicKey, err := PemFromRsaSsaPkcs1Sha256KeysetHandle(publicHandle)
	if err != nil {
		t.Fatalf("PemFromRsaSsaPkcs1Sha256KeysetHandle(handle) err = %v, want nil", err)
	}

	// Import public key and verify signature
	importedHandle, err := PemToRsaSsaPkcs1Sha256KeysetHandle(pemRsaPublicKey)
	if err != nil {
		t.Fatalf("PemToRsaSsaPkcs1Sha256KeysetHandle(pemRsaPublicKey) err = %v, want nil", err)
	}
	verifier, err := signature.NewVerifier(importedHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier(importedHandle) err = %v, want nil", err)
	}
	if err := verifier.Verify(sign, data); err != nil {
		t.Errorf("verifier.Verify(sign, data) err = %q, want nil", err)
	}
}

func TestPemFromRsaSsaPkcs1Sha256KeysetHandleSerialization(t *testing.T) {
	// Go equivalent of this test:
	// http://google3/third_party/tink/integration/javatests/com/google/crypto/tink/pem/PemKeyConverterTest.java;l=120;rcl=544586565
	modulus, err :=
		hex.DecodeString("a07887f373378196b0b748cdf31c14735ccfa0f117acafdaa21fde4b6e7559390b834e7b92e9e1cc9d49fc0fe6cfb60429652b4bf9a7768f71fc4271ca6fef4e431192ebdc98630bfb94c5baf18b4cf7881d84483e4c44c22db15a9627705a0b42a26d6f3d6009aee0d2a71bedf4d4b0ee6b6fec2f16e1277ecaa3bdedba406473a476d1688df0fad1da795526c7e641981b4812b05b692d60c60b2bfa424c8b620f40dc9dba59e2c710e7ee750b3e134c1f71f43210688aff17aaa41cdb5668753f0006b1cf951bc5951f4d89a31196985ea55c0966c3662bcfe4e4cd34f12e4afd7e5c4a130739b1017d6a583882fd72db1a67418702c8b01353ccf75b7b93faec0e0be36211d5f2bd910e1552323711bbeb73858f899cc1ec063ef67d88e0c699d5a689c52106f06e960f09d2a3cf84f53bbea2a473edf2e6e0176801d3fa1c2d358e1e5a26f646ac93796ec1fadc6991c0ec19c9dd90b25a2dd3bf73d2cf1eea8867f96caa5a2df54973acb2a2da0a1367ec74afbb968f517765238d1769")
	if err != nil {
		t.Fatalf("hex.DecodeString() err = %v, want nil", err)
	}
	params, err := rsassapkcs1.NewParameters(len(modulus)*8, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantNoPrefix)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewParameters() err = %v, want nil", err)
	}
	tinkPublicKey, err := rsassapkcs1.NewPublicKey(modulus, 0, params)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewPublicKey() err = %v, want nil", err)
	}
	km := keyset.NewManager()
	keyID, err := km.AddKey(tinkPublicKey)
	if err != nil {
		t.Fatalf("km.Add() err = %v, want nil", err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary() err = %v, want nil", err)
	}
	handle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}

	// Export pem-encoded public key
	pemEncoded, err := PemFromRsaSsaPkcs1Sha256KeysetHandle(handle)
	if err != nil {
		t.Fatalf("PemFromRsaSsaPkcs1Sha256KeysetHandle(handle) err = %v, want nil", err)
	}

	expected := `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAoHiH83M3gZawt0jN8xwU
c1zPoPEXrK/aoh/eS251WTkLg057kunhzJ1J/A/mz7YEKWUrS/mndo9x/EJxym/v
TkMRkuvcmGML+5TFuvGLTPeIHYRIPkxEwi2xWpYncFoLQqJtbz1gCa7g0qcb7fTU
sO5rb+wvFuEnfsqjve26QGRzpHbRaI3w+tHaeVUmx+ZBmBtIErBbaS1gxgsr+kJM
i2IPQNydulnixxDn7nULPhNMH3H0MhBoiv8XqqQc21ZodT8ABrHPlRvFlR9NiaMR
lphepVwJZsNmK8/k5M008S5K/X5cShMHObEBfWpYOIL9ctsaZ0GHAsiwE1PM91t7
k/rsDgvjYhHV8r2RDhVSMjcRu+tzhY+JnMHsBj72fYjgxpnVponFIQbwbpYPCdKj
z4T1O76ipHPt8ubgF2gB0/ocLTWOHlom9kask3luwfrcaZHA7BnJ3ZCyWi3Tv3PS
zx7qiGf5bKpaLfVJc6yyotoKE2fsdK+7lo9Rd2UjjRdpAgMBAAE=
-----END PUBLIC KEY-----`

	pemEncodedString := strings.TrimRight(string(pemEncoded), "\n")
	if diff := cmp.Diff(expected, pemEncodedString); diff != "" {
		t.Errorf("TestPemFromRsaSsaPkcs1Sha256KeysetHandleSerialization failed. diff (-want +got):\n%s", diff)
	}

	// Read the PEM again to ensure things worked.
	_, err = PemToRsaSsaPkcs1Sha256KeysetHandle([]byte(pemEncodedString))
	if err != nil {
		t.Fatalf("PemToRsaSsaPkcs1Sha256KeysetHandle(pemEncoded) err = %v, want nil", err)
	}
}

func TestPemFromRsaSsaPkcs1Sha256KeysetHandle_isInverseOfPemToRsaSsaPkcs1Sha256KeysetHandle(t *testing.T) {
	handle, err := PemToRsaSsaPkcs1Sha256KeysetHandle([]byte(rsaPubKeyPKIX))
	if err != nil {
		t.Fatal(err)
	}

	pemEncoded, err := PemFromRsaSsaPkcs1Sha256KeysetHandle(handle)
	if err != nil {
		t.Fatal(err)
	}

	pemEncodedString := strings.TrimRight(string(pemEncoded), "\n")
	if diff := cmp.Diff(rsaPubKeyPKIX, pemEncodedString); diff != "" {
		t.Errorf("TestPemFromRsaSsaPkcs1Sha256KeysetHandle_isInverseOfPemToRsaSsaPkcs1Sha256KeysetHandle failed. diff (-want +got):\n%s", diff)
	}
}

func TestPemFromRsaSsaPkcs1Sha256KeysetHandleWithPrivateKey(t *testing.T) {
	template := signature.RSA_SSA_PKCS1_3072_SHA256_F4_RAW_Key_Template()
	privHandle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatal(err)
	}

	_, err = PemFromRsaSsaPkcs1Sha256KeysetHandle(privHandle)
	if err == nil {
		t.Error("PemFromRsaSsaPkcs1Sha256KeysetHandle(privHandle) err = nil, want error")
	}
}

func TestPemFromRsaSsaPkcs1Sha256KeysetHandleFailsWithUnsupportedHashing(t *testing.T) {
	template := signature.RSA_SSA_PSS_4096_SHA512_64_F4_Raw_Key_Template() // This template uses SHA512 hashing
	privHandle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := privHandle.Public()
	if err != nil {
		t.Fatal(err)
	}
	_, err = PemFromRsaSsaPkcs1Sha256KeysetHandle(handle)
	if err == nil {
		t.Error("PemFromRsaSsaPkcs1Sha256KeysetHandle(handle) err = nil, want error")
	}
}

func TestPemFromRsaSsaPkcs1Sha256KeysetHandleFailsWithTinkOutputPrefix(t *testing.T) {
	template := signature.RSA_SSA_PKCS1_3072_SHA256_F4_Key_Template()
	privHandle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := privHandle.Public()
	if err != nil {
		t.Fatal(err)
	}
	_, err = PemFromRsaSsaPkcs1Sha256KeysetHandle(handle)
	if err == nil {
		t.Error("PemFromRsaSsaPkcs1Sha256KeysetHandle(handle) err = nil, want error")
	}
}

func TestPemFromRsaSsaPkcs1Sha256KeysetHandle_failsForRsaSsaPkixPublicKey(t *testing.T) {
	handle, err := PemToRsaSsaPssSha256KeysetHandle([]byte(rsaPubKeyPKIX))
	if err != nil {
		t.Fatal(err)
	}

	_, err = PemFromRsaSsaPkcs1Sha256KeysetHandle(handle)
	if err == nil {
		t.Error("PemFromRsaSsaPkcs1Sha256KeysetHandle(handle) err = nil, want error")
	}
}

func TestPemFromRsaSsaPkcs1Sha256KeysetHandle_failsWithEmptyHandle(t *testing.T) {
	handle := &keyset.Handle{}
	if _, err := PemFromRsaSsaPkcs1Sha256KeysetHandle(handle); err == nil {
		t.Error("PemFromRsaSsaPkcs1Sha256KeysetHandle(handle) err = nil, want error")
	}
}
