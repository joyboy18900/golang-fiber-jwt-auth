package token

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGenerateVerifyRoundTrip(t *testing.T) {
	secret := []byte("test-secret")
	claims := Claims{
		Sub:  "42",
		Role: "user",
		Typ:  "access",
		Iat:  time.Now().Unix(),
		Exp:  time.Now().Add(time.Minute).Unix(),
	}

	tok, err := Generate(secret, claims)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	got, err := Verify(secret, tok, "access")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if got.Sub != claims.Sub || got.Role != claims.Role || got.Typ != claims.Typ {
		t.Fatalf("Verify() claims = %+v, want %+v", got, claims)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	secret := []byte("test-secret")
	claims := Claims{Sub: "42", Role: "user", Typ: "access", Exp: time.Now().Add(time.Minute).Unix()}

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
	tamperedPayload := append([]byte{}, payload...)
	tamperedPayload[0] ^= 0xFF
	parts[1] = base64.RawURLEncoding.EncodeToString(tamperedPayload)
	tampered := strings.Join(parts, ".")

	if _, err := Verify(secret, tampered, "access"); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify() error = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	secret := []byte("test-secret")
	claims := Claims{Sub: "42", Role: "user", Typ: "access", Exp: time.Now().Add(-time.Minute).Unix()}

	tok, err := Generate(secret, claims)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if _, err := Verify(secret, tok, "access"); !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify() error = %v, want ErrExpired", err)
	}
}

func TestVerifyRejectsWrongType(t *testing.T) {
	secret := []byte("test-secret")
	claims := Claims{Sub: "42", Role: "user", Typ: "access", Exp: time.Now().Add(time.Minute).Unix()}

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

	header, err := encodeSegment(Header{Alg: "none", Typ: "JWT"})
	if err != nil {
		t.Fatalf("encodeSegment(header) error = %v", err)
	}
	payload, err := encodeSegment(Claims{Sub: "42", Typ: "access", Exp: time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatalf("encodeSegment(payload) error = %v", err)
	}
	forged := header + "." + payload + "."

	if _, err := Verify(secret, forged, "access"); !errors.Is(err, ErrInvalidAlg) {
		t.Fatalf("Verify() error = %v, want ErrInvalidAlg", err)
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	claims := Claims{Sub: "42", Role: "user", Typ: "access", Exp: time.Now().Add(time.Minute).Unix()}

	tok, err := Generate([]byte("secret-a"), claims)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if _, err := Verify([]byte("secret-b"), tok, "access"); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify() error = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRejectsMalformedToken(t *testing.T) {
	if _, err := Verify([]byte("secret"), "not-a-jwt", "access"); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("Verify() error = %v, want ErrMalformedToken", err)
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
	if accessClaims.Sub != "7" || accessClaims.Role != "admin" {
		t.Fatalf("access claims = %+v, want sub=7 role=admin", accessClaims)
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
	if refreshClaims.Jti != jti {
		t.Fatalf("refresh claims.Jti = %q, want %q", refreshClaims.Jti, jti)
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
