package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang-fiber-jwt-auth/errs"
	"golang-fiber-jwt-auth/mock/mock_repository"
	"golang-fiber-jwt-auth/repository"
	"golang-fiber-jwt-auth/service"
	"golang-fiber-jwt-auth/token"

	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"
)

const (
	testAccessTTL  = time.Minute
	testRefreshTTL = time.Hour
)

var (
	testAccessSecret  = []byte("access-secret")
	testRefreshSecret = []byte("refresh-secret")
)

func newAuthService(t *testing.T, userRepo repository.UserRepository, refreshRepo repository.RefreshTokenRepository) service.AuthService {
	t.Helper()
	return service.NewAuthService(userRepo, refreshRepo, testAccessSecret, testRefreshSecret, testAccessTTL, testRefreshTTL)
}

func TestAuthService_Register(t *testing.T) {
	tests := []struct {
		name      string
		req       service.RegisterRequest
		setup     func(userRepo *mock_repository.MockUserRepository)
		wantErr   error
		wantEmail string
	}{
		{
			name: "success",
			req:  service.RegisterRequest{Email: "new@example.com", Password: "password123"},
			setup: func(userRepo *mock_repository.MockUserRepository) {
				userRepo.EXPECT().FindByEmail(gomock.Any(), "new@example.com").
					Return(nil, repository.ErrUserNotFound)
				userRepo.EXPECT().Create(gomock.Any(), gomock.Any()).
					Return(&repository.User{ID: 1, Email: "new@example.com", Role: "user"}, nil)
			},
			wantEmail: "new@example.com",
		},
		{
			name: "duplicate email",
			req:  service.RegisterRequest{Email: "taken@example.com", Password: "password123"},
			setup: func(userRepo *mock_repository.MockUserRepository) {
				userRepo.EXPECT().FindByEmail(gomock.Any(), "taken@example.com").
					Return(&repository.User{ID: 1, Email: "taken@example.com"}, nil)
			},
			wantErr: errs.AppError{Code: 422},
		},
		{
			name:    "password too short",
			req:     service.RegisterRequest{Email: "short@example.com", Password: "abc"},
			setup:   func(userRepo *mock_repository.MockUserRepository) {},
			wantErr: errs.AppError{Code: 422},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			userRepo := mock_repository.NewMockUserRepository(ctrl)
			refreshRepo := mock_repository.NewMockRefreshTokenRepository(ctrl)
			tc.setup(userRepo)

			svc := newAuthService(t, userRepo, refreshRepo)
			got, err := svc.Register(context.Background(), tc.req)

			if tc.wantErr != nil {
				var appErr errs.AppError
				if !errors.As(err, &appErr) || appErr.Code != tc.wantErr.(errs.AppError).Code {
					t.Fatalf("Register() error = %v, want AppError code %d", err, tc.wantErr.(errs.AppError).Code)
				}
				return
			}

			if err != nil {
				t.Fatalf("Register() unexpected error = %v", err)
			}
			if got.Email != tc.wantEmail {
				t.Fatalf("Register() email = %q, want %q", got.Email, tc.wantEmail)
			}
		})
	}
}

func TestAuthService_Login(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword() error = %v", err)
	}
	existingUser := &repository.User{ID: 7, Email: "user@example.com", PasswordHash: string(hash), Role: "user"}

	tests := []struct {
		name    string
		req     service.LoginRequest
		setup   func(userRepo *mock_repository.MockUserRepository, refreshRepo *mock_repository.MockRefreshTokenRepository)
		wantErr int
	}{
		{
			name: "success",
			req:  service.LoginRequest{Email: "user@example.com", Password: "correct-password"},
			setup: func(userRepo *mock_repository.MockUserRepository, refreshRepo *mock_repository.MockRefreshTokenRepository) {
				userRepo.EXPECT().FindByEmail(gomock.Any(), "user@example.com").Return(existingUser, nil)
				refreshRepo.EXPECT().Store(gomock.Any(), gomock.Any(), existingUser.ID, testRefreshTTL).Return(nil)
			},
		},
		{
			name: "wrong password",
			req:  service.LoginRequest{Email: "user@example.com", Password: "wrong-password"},
			setup: func(userRepo *mock_repository.MockUserRepository, refreshRepo *mock_repository.MockRefreshTokenRepository) {
				userRepo.EXPECT().FindByEmail(gomock.Any(), "user@example.com").Return(existingUser, nil)
			},
			wantErr: 422,
		},
		{
			name: "unknown email",
			req:  service.LoginRequest{Email: "nobody@example.com", Password: "whatever"},
			setup: func(userRepo *mock_repository.MockUserRepository, refreshRepo *mock_repository.MockRefreshTokenRepository) {
				userRepo.EXPECT().FindByEmail(gomock.Any(), "nobody@example.com").Return(nil, repository.ErrUserNotFound)
			},
			wantErr: 422,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			userRepo := mock_repository.NewMockUserRepository(ctrl)
			refreshRepo := mock_repository.NewMockRefreshTokenRepository(ctrl)
			tc.setup(userRepo, refreshRepo)

			svc := newAuthService(t, userRepo, refreshRepo)
			got, err := svc.Login(context.Background(), tc.req)

			if tc.wantErr != 0 {
				var appErr errs.AppError
				if !errors.As(err, &appErr) || appErr.Code != tc.wantErr {
					t.Fatalf("Login() error = %v, want AppError code %d", err, tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Login() unexpected error = %v", err)
			}
			if got.AccessToken == "" || got.RefreshToken == "" {
				t.Fatal("Login() returned an empty token")
			}
		})
	}
}

func TestAuthService_Refresh(t *testing.T) {
	user := &repository.User{ID: 7, Email: "user@example.com", Role: "user"}
	validRefreshToken, jti, err := token.GenerateRefreshToken(testRefreshSecret, "7", "user", testRefreshTTL)
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}
	invalidSignatureToken, _, err := token.GenerateRefreshToken([]byte("wrong-secret"), "7", "user", testRefreshTTL)
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}

	tests := []struct {
		name    string
		req     service.RefreshRequest
		setup   func(userRepo *mock_repository.MockUserRepository, refreshRepo *mock_repository.MockRefreshTokenRepository)
		wantErr int
	}{
		{
			name: "success",
			req:  service.RefreshRequest{RefreshToken: validRefreshToken},
			setup: func(userRepo *mock_repository.MockUserRepository, refreshRepo *mock_repository.MockRefreshTokenRepository) {
				refreshRepo.EXPECT().Get(gomock.Any(), jti).Return(user.ID, nil)
				userRepo.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
			},
		},
		{
			name: "invalid signature",
			req:  service.RefreshRequest{RefreshToken: invalidSignatureToken},
			setup: func(userRepo *mock_repository.MockUserRepository, refreshRepo *mock_repository.MockRefreshTokenRepository) {
			},
			wantErr: 401,
		},
		{
			name: "revoked or expired in redis",
			req:  service.RefreshRequest{RefreshToken: validRefreshToken},
			setup: func(userRepo *mock_repository.MockUserRepository, refreshRepo *mock_repository.MockRefreshTokenRepository) {
				refreshRepo.EXPECT().Get(gomock.Any(), jti).Return(int64(0), repository.ErrRefreshTokenNotFound)
			},
			wantErr: 401,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			userRepo := mock_repository.NewMockUserRepository(ctrl)
			refreshRepo := mock_repository.NewMockRefreshTokenRepository(ctrl)
			tc.setup(userRepo, refreshRepo)

			svc := newAuthService(t, userRepo, refreshRepo)
			got, err := svc.Refresh(context.Background(), tc.req)

			if tc.wantErr != 0 {
				var appErr errs.AppError
				if !errors.As(err, &appErr) || appErr.Code != tc.wantErr {
					t.Fatalf("Refresh() error = %v, want AppError code %d", err, tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Refresh() unexpected error = %v", err)
			}
			if got.AccessToken == "" {
				t.Fatal("Refresh() returned an empty access token")
			}
		})
	}
}

func TestAuthService_Logout(t *testing.T) {
	validRefreshToken, jti, err := token.GenerateRefreshToken(testRefreshSecret, "7", "user", testRefreshTTL)
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}

	ctrl := gomock.NewController(t)
	userRepo := mock_repository.NewMockUserRepository(ctrl)
	refreshRepo := mock_repository.NewMockRefreshTokenRepository(ctrl)
	refreshRepo.EXPECT().Revoke(gomock.Any(), jti).Return(nil)

	svc := newAuthService(t, userRepo, refreshRepo)
	if err := svc.Logout(context.Background(), service.LogoutRequest{RefreshToken: validRefreshToken}); err != nil {
		t.Fatalf("Logout() unexpected error = %v", err)
	}
}

func TestAuthService_Logout_InvalidToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mock_repository.NewMockUserRepository(ctrl)
	refreshRepo := mock_repository.NewMockRefreshTokenRepository(ctrl)

	svc := newAuthService(t, userRepo, refreshRepo)
	err := svc.Logout(context.Background(), service.LogoutRequest{RefreshToken: "not-a-token"})

	var appErr errs.AppError
	if !errors.As(err, &appErr) || appErr.Code != 401 {
		t.Fatalf("Logout() error = %v, want AppError code 401", err)
	}
}
