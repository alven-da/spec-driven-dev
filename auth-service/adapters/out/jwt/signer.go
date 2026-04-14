package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

type Signer struct {
	privateKey *rsa.PrivateKey
	issuer     string
	kid        string
}

func NewSigner(issuer string) (*Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	kidBytes := make([]byte, 8)
	if _, err := rand.Read(kidBytes); err != nil {
		return nil, err
	}

	return &Signer{
		privateKey: privateKey,
		issuer:     issuer,
		kid:        hex.EncodeToString(kidBytes),
	}, nil
}

func (s *Signer) SignToken(subject, audience string, ttl time.Duration, additionalClaims map[string]any) (string, error) {
	now := time.Now().UTC()
	claims := jwtlib.MapClaims{
		"iss": s.issuer,
		"sub": subject,
		"aud": audience,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	for key, value := range additionalClaims {
		claims[key] = value
	}

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.privateKey)
}

func (s *Signer) ParseAndValidate(token string) (map[string]any, error) {
	parsed, err := jwtlib.Parse(token, func(t *jwtlib.Token) (any, error) {
		if t.Method.Alg() != jwtlib.SigningMethodRS256.Alg() {
			return nil, errors.New("unexpected jwt alg")
		}
		return &s.privateKey.PublicKey, nil
	}, jwtlib.WithIssuer(s.issuer))
	if err != nil || !parsed.Valid {
		return nil, errors.New("invalid token")
	}

	mapClaims, ok := parsed.Claims.(jwtlib.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return mapClaims, nil
}

func (s *Signer) JWKS() map[string]any {
	publicKey := s.privateKey.PublicKey
	modulus := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	exponent := base64.RawURLEncoding.EncodeToString(bigEndianBytes(publicKey.E))

	return map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": s.kid,
				"n":   modulus,
				"e":   exponent,
			},
		},
	}
}

func (s *Signer) Issuer() string {
	return s.issuer
}

func bigEndianBytes(value int) []byte {
	if value == 0 {
		return []byte{0}
	}

	out := make([]byte, 0, 4)
	for value > 0 {
		out = append([]byte{byte(value & 0xff)}, out...)
		value >>= 8
	}
	return out
}
