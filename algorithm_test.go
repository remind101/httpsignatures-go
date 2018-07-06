package httpsignatures

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

// PEM encoded representation of the key specified in JWK format in
// https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#appendix-A.3
//
// {"kty":"EC", "crv":"P-256", "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0", "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI" }
const joseECDSAKey = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgjpsQnnGQmL+YBIff
H1136cspYG6+0iY7X1fCE9+E9LKgCgYIKoZIzj0DAQehRANCAAR/zc4ncPbEXUGD
y+5v20t7WAczNXvp7xO6z248e9FURcfxRM0bvZt+hyzf7bnuufSzaV1uqQskrYpG
IyiFiOWt
-----END PRIVATE KEY-----`

// This ensures that the ECDSA signature generation/verification algorithm
// matches the spec defined in
// https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-20#section-3.4
func TestECDSASignatureAlgorithm(t *testing.T) {
	block, _ := pem.Decode([]byte(joseECDSAKey))
	k, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	key := k.(*ecdsa.PrivateKey)

	verify := ecdsaVerify(crypto.SHA256)
	sign := ecdsaSign(crypto.SHA256)

	tests := []struct {
		// The message that was signed.
		message []byte
		// The signature of the message, as provided in the RFC. This
		// will be checked to ensure that it can be verified.
		signature string
	}{
		{
			message:   []byte("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"),
			signature: "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q",
		},
	}

	for _, tt := range tests {
		signature, err := base64.RawURLEncoding.DecodeString(tt.signature)
		if err != nil {
			t.Fatal(err)
		}

		// Ensure that we can verify signatures produced by something
		// other than ourselves.
		ok := verify(&key.PublicKey, tt.message, signature)
		if !ok {
			t.Fatal("Expected the signature to be valid")
		}

		// Make sure that we can also generate a signature that can be
		// verified.
		signature, err = sign(key, tt.message)
		ok = verify(&key.PublicKey, tt.message, signature)
		if !ok {
			t.Fatal("Expected the signature to be valid")
		}
	}
}
