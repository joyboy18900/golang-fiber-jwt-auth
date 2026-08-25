package handler_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"golang-fiber-jwt-auth/handler"
	"golang-fiber-jwt-auth/token"

	"github.com/gofiber/fiber/v2"
)

func newTestApp(secret []byte, requireRole ...string) *fiber.App {
	app := fiber.New()

	handlers := []fiber.Handler{handler.JWTMiddleware(secret)}
	if len(requireRole) > 0 {
		handlers = append(handlers, handler.RequireRole(requireRole...))
	}
	handlers = append(handlers, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	app.Get("/protected", handlers...)
	return app
}

func TestJWTMiddleware(t *testing.T) {
	secret := []byte("test-secret")

	validToken, err := token.GenerateAccessToken(secret, "1", "user", time.Minute)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}
	expiredToken, err := token.GenerateAccessToken(secret, "1", "user", -time.Minute)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{name: "valid token", authHeader: "Bearer " + validToken, wantStatus: fiber.StatusOK},
		{name: "missing header", authHeader: "", wantStatus: fiber.StatusUnauthorized},
		{name: "malformed header", authHeader: "Token abc", wantStatus: fiber.StatusUnauthorized},
		{name: "expired token", authHeader: "Bearer " + expiredToken, wantStatus: fiber.StatusUnauthorized},
	}

	app := newTestApp(secret)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(fiber.MethodGet, "/protected", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}

			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test() error = %v", err)
			}
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
		})
	}
}

func TestRequireRole(t *testing.T) {
	secret := []byte("test-secret")

	userToken, err := token.GenerateAccessToken(secret, "1", "user", time.Minute)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}
	adminToken, err := token.GenerateAccessToken(secret, "2", "admin", time.Minute)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	app := newTestApp(secret, "admin")

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{name: "admin allowed", authHeader: "Bearer " + adminToken, wantStatus: fiber.StatusOK},
		{name: "user forbidden", authHeader: "Bearer " + userToken, wantStatus: fiber.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(fiber.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", tc.authHeader)

			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test() error = %v", err)
			}
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
		})
	}
}
