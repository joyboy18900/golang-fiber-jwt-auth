package token

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateVerifyRoundTrip(t *testing.T) {
	secret := []byte("test-secret")
	claims := Claims{
		Role: "user",
		Typ:  "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "42",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
	}

	tok, err := Generate(secret, claims)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	got, err := Verify(secret, tok, "access")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if got.Subject != claims.Subject || got.Role != claims.Role || got.Typ != claims.Typ {
		t.Fatalf("Verify() claims = %+v, want %+v", got, claims)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	secret := []byte("test-secret")
	claims := Claims{
		Role: "user",
		Typ:  "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "42",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
	}

	tok, err := Generate(secret, claims)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	idx := bytes.IndexAny(payload, "0123456789")
	if idx == -1 {
		t.Fatal("payload has no digit to tamper with")
	}
	tamperedPayload := append([]byte{}, payload...)
	if tamperedPayload[idx] == '9' {
		tamperedPayload[idx] = '8'
	} else {
		tamperedPayload[idx]++
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(tamperedPayload)
	tampered := strings.Join(parts, ".")

	if _, err := Verify(secret, tampered, "access"); !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		t.Fatalf("Verify() error = %v, want jwt.ErrTokenSignatureInvalid", err)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	secret := []byte("test-secret")
	claims := Claims{
		Role: "user",
		Typ:  "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "42",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	}

	tok, err := Generate(secret, claims)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if _, err := Verify(secret, tok, "access"); !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("Verify() error = %v, want jwt.ErrTokenExpired", err)
	}
}

func TestVerifyRejectsWrongType(t *testing.T) {
	secret := []byte("test-secret")
	claims := Claims{
		Role: "user",
		Typ:  "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "42",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
	}

	tok, err := Generate(secret, claims)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if _, err := Verify(secret, tok, "refresh"); !errors.Is(err, ErrWrongType) {
		t.Fatalf("Verify() error = %v, want ErrWrongType", err)
	}
}

func TestVerifyRejectsUnsupportedAlg(t *testing.T) {
	secret := []byte("test-secret")
	claims := Claims{
		Role: "user",
		Typ:  "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "42",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	forged, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("SignedString(none) error = %v", err)
	}

	if _, err := Verify(secret, forged, "access"); err == nil {
		t.Fatal("Verify() error = nil, want a rejection of the unsigned token")
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	claims := Claims{
		Role: "user",
		Typ:  "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "42",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
	}

	tok, err := Generate([]byte("secret-a"), claims)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if _, err := Verify([]byte("secret-b"), tok, "access"); !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		t.Fatalf("Verify() error = %v, want jwt.ErrTokenSignatureInvalid", err)
	}
}

func TestVerifyRejectsMalformedToken(t *testing.T) {
	if _, err := Verify([]byte("secret"), "not-a-jwt", "access"); !errors.Is(err, jwt.ErrTokenMalformed) {
		t.Fatalf("Verify() error = %v, want jwt.ErrTokenMalformed", err)
	}
}

func TestGenerateAccessAndRefreshTokenHelpers(t *testing.T) {
	accessSecret := []byte("access-secret")
	refreshSecret := []byte("refresh-secret")

	accessTok, err := GenerateAccessToken(accessSecret, "7", "admin", time.Minute)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}
	accessClaims, err := Verify(accessSecret, accessTok, "access")
	if err != nil {
		t.Fatalf("Verify(access) error = %v", err)
	}
	if accessClaims.Subject != "7" || accessClaims.Role != "admin" {
		t.Fatalf("access claims = %+v, want subject=7 role=admin", accessClaims)
	}

	refreshTok, jti, err := GenerateRefreshToken(refreshSecret, "7", "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}
	if jti == "" {
		t.Fatal("GenerateRefreshToken() returned empty jti")
	}
	refreshClaims, err := Verify(refreshSecret, refreshTok, "refresh")
	if err != nil {
		t.Fatalf("Verify(refresh) error = %v", err)
	}
	if refreshClaims.ID != jti {
		t.Fatalf("refresh claims.ID = %q, want %q", refreshClaims.ID, jti)
	}
}

func TestNewJTIIsUniqueAndNonEmpty(t *testing.T) {
	a, err := NewJTI()
	if err != nil {
		t.Fatalf("NewJTI() error = %v", err)
	}
	b, err := NewJTI()
	if err != nil {
		t.Fatalf("NewJTI() error = %v", err)
	}
	if a == "" || b == "" {
		t.Fatal("NewJTI() returned empty string")
	}
	if a == b {
		t.Fatal("NewJTI() returned the same value twice")
	}
}
