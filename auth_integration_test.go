package main_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang-fiber-jwt-auth/handler"
	"golang-fiber-jwt-auth/repository"
	"golang-fiber-jwt-auth/service"

	"github.com/gofiber/fiber/v2"
)

type fakeUserRepository struct {
	mu     sync.Mutex
	users  map[string]repository.User
	nextID int64
}

func newFakeUserRepository() *fakeUserRepository {
	return &fakeUserRepository{users: make(map[string]repository.User), nextID: 1}
}

func (f *fakeUserRepository) Create(_ context.Context, user repository.User) (*repository.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	user.ID = f.nextID
	f.nextID++
	f.users[user.Email] = user

	created := user
	return &created, nil
}

func (f *fakeUserRepository) FindByEmail(_ context.Context, email string) (*repository.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	user, ok := f.users[email]
	if !ok {
		return nil, repository.ErrUserNotFound
	}
	return &user, nil
}

func (f *fakeUserRepository) FindByID(_ context.Context, id int64) (*repository.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, user := range f.users {
		if user.ID == id {
			return &user, nil
		}
	}
	return nil, repository.ErrUserNotFound
}

type fakeRefreshTokenRepository struct {
	mu     sync.Mutex
	tokens map[string]int64
}

func newFakeRefreshTokenRepository() *fakeRefreshTokenRepository {
	return &fakeRefreshTokenRepository{tokens: make(map[string]int64)}
}

func (f *fakeRefreshTokenRepository) Store(_ context.Context, jti string, userID int64, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.tokens[jti] = userID
	return nil
}

func (f *fakeRefreshTokenRepository) Get(_ context.Context, jti string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	userID, ok := f.tokens[jti]
	if !ok {
		return 0, repository.ErrRefreshTokenNotFound
	}
	return userID, nil
}

func (f *fakeRefreshTokenRepository) Revoke(_ context.Context, jti string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.tokens, jti)
	return nil
}

const (
	testAccessSecretKey  = "integration-access-secret"
	testRefreshSecretKey = "integration-refresh-secret"
)

func newIntegrationTestApp() *fiber.App {
	userRepo := newFakeUserRepository()
	refreshRepo := newFakeRefreshTokenRepository()

	authSvc := service.NewAuthService(
		userRepo,
		refreshRepo,
		[]byte(testAccessSecretKey),
		[]byte(testRefreshSecretKey),
		time.Minute,
		time.Hour,
	)
	authHdlr := handler.NewAuthHandler(authSvc)

	app := fiber.New()
	app.Post("/auth/register", authHdlr.Register)
	app.Post("/auth/login", authHdlr.Login)
	app.Post("/auth/refresh", authHdlr.Refresh)
	app.Post("/auth/logout", authHdlr.Logout)
	app.Get("/me", handler.JWTMiddleware([]byte(testAccessSecretKey)), authHdlr.Me)

	return app
}

func doJSON(t *testing.T, app *fiber.App, method, path string, body any) *http.Response {
	t.Helper()

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatalf("encode request body: %v", err)
	}

	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	return resp
}

func TestAuthFlow_RevokedRefreshTokenIsRejected(t *testing.T) {
	app := newIntegrationTestApp()
	credentials := map[string]string{"email": "flow@example.com", "password": "password123"}

	resp := doJSON(t, app, fiber.MethodPost, "/auth/register", credentials)
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("register status = %d, want %d", resp.StatusCode, fiber.StatusCreated)
	}

	resp = doJSON(t, app, fiber.MethodPost, "/auth/login", credentials)
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("login status = %d, want %d", resp.StatusCode, fiber.StatusOK)
	}

	var loginResp service.LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if loginResp.RefreshToken == "" {
		t.Fatal("login response has an empty refresh token")
	}

	refreshRequest := map[string]string{"refresh_token": loginResp.RefreshToken}

	resp = doJSON(t, app, fiber.MethodPost, "/auth/refresh", refreshRequest)
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("pre-logout refresh status = %d, want %d", resp.StatusCode, fiber.StatusOK)
	}

	resp = doJSON(t, app, fiber.MethodPost, "/auth/logout", refreshRequest)
	if resp.StatusCode != fiber.StatusNoContent {
		t.Fatalf("logout status = %d, want %d", resp.StatusCode, fiber.StatusNoContent)
	}

	resp = doJSON(t, app, fiber.MethodPost, "/auth/refresh", refreshRequest)
	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("post-logout refresh status = %d, want %d", resp.StatusCode, fiber.StatusUnauthorized)
	}
}
