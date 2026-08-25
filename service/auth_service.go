package service

import (
	"context"
	"errors"
	"strconv"
	"time"

	"golang-fiber-jwt-auth/errs"
	"golang-fiber-jwt-auth/logs"
	"golang-fiber-jwt-auth/repository"
	"golang-fiber-jwt-auth/token"

	"golang.org/x/crypto/bcrypt"
)

const minPasswordLength = 8

type authService struct {
	userRepo      repository.UserRepository
	refreshRepo   repository.RefreshTokenRepository
	accessSecret  []byte
	refreshSecret []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
}

func NewAuthService(
	userRepo repository.UserRepository,
	refreshRepo repository.RefreshTokenRepository,
	accessSecret []byte,
	refreshSecret []byte,
	accessTTL time.Duration,
	refreshTTL time.Duration,
) AuthService {
	return authService{
		userRepo:      userRepo,
		refreshRepo:   refreshRepo,
		accessSecret:  accessSecret,
		refreshSecret: refreshSecret,
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
	}
}

func (s authService) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	if req.Email == "" || len(req.Password) < minPasswordLength {
		return nil, errs.NewValidationError("email and a password of at least 8 characters are required")
	}

	_, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err == nil {
		return nil, errs.NewValidationError("email already registered")
	}
	if !errors.Is(err, repository.ErrUserNotFound) {
		logs.Error(err)
		return nil, errs.NewUnexpectedError()
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		logs.Error(err)
		return nil, errs.NewUnexpectedError()
	}

	created, err := s.userRepo.Create(ctx, repository.User{
		Email:        req.Email,
		PasswordHash: string(hash),
		Role:         "user",
	})
	if err != nil {
		logs.Error(err)
		return nil, errs.NewUnexpectedError()
	}

	return &RegisterResponse{ID: created.ID, Email: created.Email, Role: created.Role}, nil
}

func (s authService) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	invalidCredentials := errs.NewValidationError("invalid email or password")

	user, err := s.userRepo.FindByEmail(ctx, req.Email)
	if errors.Is(err, repository.ErrUserNotFound) {
		return nil, invalidCredentials
	}
	if err != nil {
		logs.Error(err)
		return nil, errs.NewUnexpectedError()
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		return nil, invalidCredentials
	}

	userID := strconv.FormatInt(user.ID, 10)

	accessToken, err := token.GenerateAccessToken(s.accessSecret, userID, user.Role, s.accessTTL)
	if err != nil {
		logs.Error(err)
		return nil, errs.NewUnexpectedError()
	}

	refreshToken, jti, err := token.GenerateRefreshToken(s.refreshSecret, userID, user.Role, s.refreshTTL)
	if err != nil {
		logs.Error(err)
		return nil, errs.NewUnexpectedError()
	}

	if err := s.refreshRepo.Store(ctx, jti, user.ID, s.refreshTTL); err != nil {
		logs.Error(err)
		return nil, errs.NewUnexpectedError()
	}

	return &LoginResponse{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (s authService) Refresh(ctx context.Context, req RefreshRequest) (*RefreshResponse, error) {
	claims, err := token.Verify(s.refreshSecret, req.RefreshToken, "refresh")
	if err != nil {
		return nil, errs.NewUnauthorizedError("invalid refresh token")
	}

	userID, err := s.refreshRepo.Get(ctx, claims.Jti)
	if errors.Is(err, repository.ErrRefreshTokenNotFound) {
		return nil, errs.NewUnauthorizedError("refresh token revoked or expired")
	}
	if err != nil {
		logs.Error(err)
		return nil, errs.NewUnexpectedError()
	}

	user, err := s.userRepo.FindByID(ctx, userID)
	if errors.Is(err, repository.ErrUserNotFound) {
		return nil, errs.NewUnauthorizedError("user no longer exists")
	}
	if err != nil {
		logs.Error(err)
		return nil, errs.NewUnexpectedError()
	}

	accessToken, err := token.GenerateAccessToken(s.accessSecret, strconv.FormatInt(user.ID, 10), user.Role, s.accessTTL)
	if err != nil {
		logs.Error(err)
		return nil, errs.NewUnexpectedError()
	}

	return &RefreshResponse{AccessToken: accessToken}, nil
}

func (s authService) Logout(ctx context.Context, req LogoutRequest) error {
	claims, err := token.Verify(s.refreshSecret, req.RefreshToken, "refresh")
	if err != nil {
		return errs.NewUnauthorizedError("invalid refresh token")
	}

	if err := s.refreshRepo.Revoke(ctx, claims.Jti); err != nil {
		logs.Error(err)
		return errs.NewUnexpectedError()
	}

	return nil
}
