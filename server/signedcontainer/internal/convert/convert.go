package convert

// TODO: Remove this package and migrate to the Tink API when they publish it.
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkecdsa "github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapss"
)

const (
	// RSA default public exponent (aka F4).
	f4 = 65537
)

// unmarshalPEMToPublicKey converts a PEM-encoded byte slice into a crypto.PublicKey.
func unmarshalPEMToPublicKey(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM data found, failed to decode PEM-encoded byte slice")
	}
	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported public key type: %v", block.Type)
	}
}

// createECDSAP256SHA256WithDERNoPrefixPublicKey creates a Tink [tinkecdsa.PublicKey].
//
// The key uses P256 as the curve, SHA256 as the hash function, DER signature
// encoding and does not add an output prefix.
func createECDSAP256SHA256WithDERNoPrefixPublicKey(pubKey crypto.PublicKey) (*tinkecdsa.PublicKey, error) {
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an ECDSA public key: %v", pubKey)
	}
	ecdhPubKey, err := ecdsaPubKey.ECDH()
	if err != nil {
		return nil, err
	}
	// Turn this into a Tink key.
	params, err := tinkecdsa.NewParameters(tinkecdsa.NistP256, tinkecdsa.SHA256, tinkecdsa.DER, tinkecdsa.VariantNoPrefix)
	if err != nil {
		return nil, err
	}
	// Will fail if the point is not on the curve.
	return tinkecdsa.NewPublicKey(ecdhPubKey.Bytes(), 0, params)
}

// PemToECDSAP256Sha256WithDEREncodingKeysetHandle converts a PEM-encoded byte
// slice into a Tink public Keyset.
//
// ECDSA Signatures need to used the ASN.1 DER encoding.
//
// The JWA RFC for ES256, ES384 and ES512 mandates a different encoding,
// so this generated with this class are not conformant with the JWA
// standard. See https://www.rfc-editor.org/rfc/rfc7518#section-3.4.
func PemToECDSAP256Sha256WithDEREncodingKeysetHandle(pemBytes []byte) (*keyset.Handle, error) {
	publicKey, err := unmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return nil, err
	}
	tinkPublicKey, err := createECDSAP256SHA256WithDERNoPrefixPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	km := keyset.NewManager()
	keyID, err := km.AddKey(tinkPublicKey)
	if err != nil {
		return nil, err
	}
	if err := km.SetPrimary(keyID); err != nil {
		return nil, err
	}
	return km.Handle()
}

// PemToRsaSsaPkcs1Sha256KeysetHandle converts a PEM-encoded byte slice into a Tink public Keyset.
//
// Note that only OID "rsaEncryption" is supported. The OIDs "sha256WithRSAEncryption",
// "sha384WithRSAEncryption" and "sha512WithRSAEncryption" are not supported.
// See RFC 4055 Section 1.2 and Section 5 for a discussion of these OIDs.
func PemToRsaSsaPkcs1Sha256KeysetHandle(pemBytes []byte) (*keyset.Handle, error) {
	publicKey, err := unmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return nil, err
	}
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not a RSA public key: %v", publicKey)
	}
	// Turn this into a Tink key.
	params, err := rsassapkcs1.NewParameters(rsaPublicKey.N.BitLen(), rsassapkcs1.SHA256, f4, rsassapkcs1.VariantNoPrefix)
	if err != nil {
		return nil, err
	}
	tinkPublicKey, err := rsassapkcs1.NewPublicKey(rsaPublicKey.N.Bytes(), 0, params)
	if err != nil {
		return nil, err
	}
	km := keyset.NewManager()
	id, err := km.AddKey(tinkPublicKey)
	if err != nil {
		return nil, err
	}
	if err := km.SetPrimary(id); err != nil {
		return nil, err
	}
	return km.Handle()
}

// PemToRsaSsaPssSha256KeysetHandle converts a PEM-encoded byte slice into a Tink public Keyset.
//
// Note that only OID "rsaEncryption" is supported. The OID "id-RSASSA-PSS" is not supported.
// See RFC 4055 Section 1.2 for a discussion of these OIDs.
func PemToRsaSsaPssSha256KeysetHandle(pemBytes []byte) (*keyset.Handle, error) {
	publicKey, err := unmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return nil, err
	}
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not a RSA public key: %v", publicKey)
	}
	// Turn this into a Tink key.
	params, err := rsassapss.NewParameters(rsassapss.ParametersValues{
		ModulusSizeBits: rsaPublicKey.N.BitLen(),
		SigHashType:     rsassapss.SHA256,
		MGF1HashType:    rsassapss.SHA256,
		PublicExponent:  rsaPublicKey.E,
		SaltLengthBytes: rsa.PSSSaltLengthAuto,
	}, rsassapss.VariantNoPrefix)
	if err != nil {
		return nil, err
	}
	tinkPublicKey, err := rsassapss.NewPublicKey(rsaPublicKey.N.Bytes(), 0, params)
	if err != nil {
		return nil, err
	}
	km := keyset.NewManager()
	id, err := km.AddKey(tinkPublicKey)
	if err != nil {
		return nil, err
	}
	if err := km.SetPrimary(id); err != nil {
		return nil, err
	}
	return km.Handle()
}

// PemFromECDSAP256Sha256WithDEREncodingKeysetHandle converts a Tink Keyset
// with one EcdsaPublicKey (over curve P-256 using SHA256 and DER signature
// encoding) into a PEM-encoded key.
//
// Note that the PEM encoded key does not have all the metadata the Tink key
// has. This can produce unexpected incompatibilities, see
// https://developers.google.com/tink/design/access_control#accessing_partial_keys
func PemFromECDSAP256Sha256WithDEREncodingKeysetHandle(handle *keyset.Handle) ([]byte, error) {
	if handle.Len() != 1 {
		return nil, fmt.Errorf("unexpected number of keys: got %v, want 1", handle.Len())
	}
	entry, err := handle.Entry(0)
	if err != nil {
		return nil, err
	}
	if entry.KeyStatus() != keyset.Enabled {
		return nil, fmt.Errorf("unsupported key status: %v, want %v", entry.KeyStatus(), keyset.Enabled)
	}
	publicKey, ok := entry.Key().(*tinkecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type: %T, want *tinkecdsa.PublicKey", entry.Key())
	}
	params := publicKey.Parameters().(*tinkecdsa.Parameters)
	if params.HashType() != tinkecdsa.SHA256 {
		return nil, fmt.Errorf("unsupported hash type: %v, want %v", params.HashType(), tinkecdsa.SHA256)
	}
	if params.CurveType() != tinkecdsa.NistP256 {
		return nil, fmt.Errorf("unsupported curve type: %v, want %v", params.CurveType(), tinkecdsa.NistP256)
	}
	if params.SignatureEncoding() != tinkecdsa.DER {
		return nil, fmt.Errorf("unsupported signature encoding: %v, want %v", params.SignatureEncoding(), tinkecdsa.DER)
	}
	if params.Variant() != tinkecdsa.VariantNoPrefix {
		return nil, fmt.Errorf("unsupported output prefix variant: %v, want %v", params.Variant(), tinkecdsa.VariantNoPrefix)
	}
	// publicKey.PublicPoint() is in the uncompressed format as defined in
	// SEC 1 v2.0, Section 2.3.3 (https://www.secg.org/sec1-v2.pdf#page=17.08).
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey.PublicPoint())
	encoded, err := x509.MarshalPKIXPublicKey(
		&ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		})
	if err != nil {
		return nil, fmt.Errorf("x509.MarshalPKIXPublicKey failed: %v", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: encoded,
	}
	return pem.EncodeToMemory(block), nil
}

// PemFromRsaSsaPkcs1Sha256KeysetHandle converts a Tink Keyset with one RsaSsaPkcs1PublicKey
// (using SHA256) into a PEM-encoded key.
//
// Note that the PEM encoded key does not have all the metadata the Tink key has.
// This can produce unexpected incompatibilities, see
// https://developers.google.com/tink/design/access_control#accessing_partial_keys
func PemFromRsaSsaPkcs1Sha256KeysetHandle(handle *keyset.Handle) ([]byte, error) {
	if handle.Len() != 1 {
		return nil, fmt.Errorf("unexpected number of keys: got %v, want 1", handle.Len())
	}
	entry, err := handle.Entry(0)
	if err != nil {
		return nil, err
	}
	if entry.KeyStatus() != keyset.Enabled {
		return nil, fmt.Errorf("unsupported key status: %v, want %v", entry.KeyStatus(), keyset.Enabled)
	}
	publicKey, ok := entry.Key().(*rsassapkcs1.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type: %T, want *rsassapkcs1.PublicKey", entry.Key())
	}
	params := publicKey.Parameters().(*rsassapkcs1.Parameters)
	if params.HashType() != rsassapkcs1.SHA256 {
		return nil, fmt.Errorf("unsupported hash type: %v, want %v", params.HashType(), rsassapkcs1.SHA256)
	}
	if params.PublicExponent() != f4 {
		return nil, fmt.Errorf("invalid public exponent: %v, want %v", params.PublicExponent(), f4)
	}
	if params.Variant() != rsassapkcs1.VariantNoPrefix {
		return nil, fmt.Errorf("unsupported output prefix variant: %v, want %v", params.Variant(), rsassapkcs1.VariantNoPrefix)
	}
	encoded, err := x509.MarshalPKIXPublicKey(
		&rsa.PublicKey{
			N: new(big.Int).SetBytes(publicKey.Modulus()),
			E: params.PublicExponent(),
		})
	if err != nil {
		return nil, fmt.Errorf("x509.MarshalPKIXPublicKey failed: %v", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: encoded,
	}
	return pem.EncodeToMemory(block), nil
}
