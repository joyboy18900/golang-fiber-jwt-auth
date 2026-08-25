package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type Claims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Typ  string `json:"typ"`
	Jti  string `json:"jti,omitempty"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

var (
	ErrMalformedToken   = errors.New("token: malformed")
	ErrInvalidAlg       = errors.New("token: unsupported algorithm")
	ErrInvalidSignature = errors.New("token: invalid signature")
	ErrExpired          = errors.New("token: expired")
	ErrWrongType        = errors.New("token: wrong token type")
)

const signingAlg = "HS256"

func NewJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func encodeSegment(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeSegment(s string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func sign(secret []byte, signingInput string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func Generate(secret []byte, claims Claims) (string, error) {
	headerB64, err := encodeSegment(Header{Alg: signingAlg, Typ: "JWT"})
	if err != nil {
		return "", err
	}
	payloadB64, err := encodeSegment(claims)
	if err != nil {
		return "", err
	}

	signingInput := headerB64 + "." + payloadB64
	sigB64 := sign(secret, signingInput)

	return signingInput + "." + sigB64, nil
}

func Verify(secret []byte, tokenString string, expectedTyp string) (Claims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return Claims{}, ErrMalformedToken
	}
	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]

	var header Header
	if err := decodeSegment(headerB64, &header); err != nil {
		return Claims{}, ErrMalformedToken
	}
	if header.Alg != signingAlg {
		return Claims{}, ErrInvalidAlg
	}

	signingInput := headerB64 + "." + payloadB64
	expectedSig := sign(secret, signingInput)
	if !hmac.Equal([]byte(expectedSig), []byte(sigB64)) {
		return Claims{}, ErrInvalidSignature
	}

	var claims Claims
	if err := decodeSegment(payloadB64, &claims); err != nil {
		return Claims{}, ErrMalformedToken
	}

	if time.Now().Unix() >= claims.Exp {
		return Claims{}, ErrExpired
	}
	if claims.Typ != expectedTyp {
		return Claims{}, ErrWrongType
	}

	return claims, nil
}

func GenerateAccessToken(secret []byte, userID string, role string, ttl time.Duration) (string, error) {
	now := time.Now()
	return Generate(secret, Claims{
		Sub:  userID,
		Role: role,
		Typ:  "access",
		Iat:  now.Unix(),
		Exp:  now.Add(ttl).Unix(),
	})
}

func GenerateRefreshToken(secret []byte, userID string, role string, ttl time.Duration) (string, string, error) {
	jti, err := NewJTI()
	if err != nil {
		return "", "", err
	}

	now := time.Now()
	tok, err := Generate(secret, Claims{
		Sub:  userID,
		Role: role,
		Typ:  "refresh",
		Jti:  jti,
		Iat:  now.Unix(),
		Exp:  now.Add(ttl).Unix(),
	})
	if err != nil {
		return "", "", err
	}

	return tok, jti, nil
}
