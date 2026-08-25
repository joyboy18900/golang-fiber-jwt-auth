package repository

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type refreshTokenRepositoryRedis struct {
	client *redis.Client
}

func NewRefreshTokenRepositoryRedis(client *redis.Client) RefreshTokenRepository {
	return refreshTokenRepositoryRedis{client: client}
}

func (r refreshTokenRepositoryRedis) Store(ctx context.Context, jti string, userID int64, ttl time.Duration) error {
	return r.client.Set(ctx, refreshTokenKey(jti), userID, ttl).Err()
}

func (r refreshTokenRepositoryRedis) Get(ctx context.Context, jti string) (int64, error) {
	val, err := r.client.Get(ctx, refreshTokenKey(jti)).Result()
	if errors.Is(err, redis.Nil) {
		return 0, ErrRefreshTokenNotFound
	}
	if err != nil {
		return 0, err
	}

	userID, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0, err
	}

	return userID, nil
}

func (r refreshTokenRepositoryRedis) Revoke(ctx context.Context, jti string) error {
	return r.client.Del(ctx, refreshTokenKey(jti)).Err()
}

func refreshTokenKey(jti string) string {
	return "refresh_token:" + jti
}
