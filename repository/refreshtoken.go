package repository

import (
	"context"
	"errors"
	"time"
)

var ErrRefreshTokenNotFound = errors.New("repository: refresh token not found")

//go:generate go tool mockgen -destination=../mock/mock_repository/refreshtoken.go golang-fiber-jwt-auth/repository RefreshTokenRepository
type RefreshTokenRepository interface {
	Store(ctx context.Context, jti string, userID int64, ttl time.Duration) error
	Get(ctx context.Context, jti string) (int64, error)
	Revoke(ctx context.Context, jti string) error
}
