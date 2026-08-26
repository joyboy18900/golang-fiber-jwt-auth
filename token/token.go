package token

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Role string `json:"role"`
	Typ  string `json:"typ"`
	jwt.RegisteredClaims
}

var ErrWrongType = errors.New("token: wrong token type")

func NewJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func Generate(secret []byte, claims Claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func Verify(secret []byte, tokenString string, expectedTyp string) (Claims, error) {
	var claims Claims
	_, err := jwt.ParseWithClaims(tokenString, &claims, func(*jwt.Token) (any, error) {
		return secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	if err != nil {
		return Claims{}, err
	}

	if claims.Typ != expectedTyp {
		return Claims{}, ErrWrongType
	}

	return claims, nil
}

func GenerateAccessToken(secret []byte, userID string, role string, ttl time.Duration) (string, error) {
	now := time.Now()
	return Generate(secret, Claims{
		Role: role,
		Typ:  "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	})
}

func GenerateRefreshToken(secret []byte, userID string, role string, ttl time.Duration) (string, string, error) {
	jti, err := NewJTI()
	if err != nil {
		return "", "", err
	}

	now := time.Now()
	tok, err := Generate(secret, Claims{
		Role: role,
		Typ:  "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	})
	if err != nil {
		return "", "", err
	}

	return tok, jti, nil
}
