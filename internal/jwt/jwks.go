package jwt

import (
	"encoding/base64"
	"math/big"
)

// JWK represents a JSON Web Key (RFC 7517)
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// OpenIDConfiguration provides discovery metadata (RFC 8414)
type OpenIDConfiguration struct {
	Issuer                string   `json:"issuer"`
	JwksURI               string   `json:"jwks_uri"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	SubjectTypesSupported  []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported       []string `json:"claims_supported"`
}

// GetJWKS generates JWKS structure for RS256 public keys
func (tm *TokenManager) GetJWKS() JWKS {
	if tm.rsaPublicKey == nil {
		return JWKS{Keys: []JWK{}}
	}

	nBytes := tm.rsaPublicKey.N.Bytes()
	eBytes := big.NewInt(int64(tm.rsaPublicKey.E)).Bytes()

	nStr := base64.RawURLEncoding.EncodeToString(nBytes)
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)

	return JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: tm.keyID,
				N:   nStr,
				E:   eStr,
			},
		},
	}
}

// GetOpenIDConfiguration returns OIDC discovery document
func (tm *TokenManager) GetOpenIDConfiguration(baseURL string) OpenIDConfiguration {
	return OpenIDConfiguration{
		Issuer:                tm.issuer,
		JwksURI:               baseURL + "/.well-known/jwks.json",
		ResponseTypesSupported: []string{"token", "id_token"},
		SubjectTypesSupported:  []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ClaimsSupported: []string{
			"sub", "email", "role", "status", "email_verified", "metadata", "iss", "aud", "exp", "iat",
		},
	}
}
