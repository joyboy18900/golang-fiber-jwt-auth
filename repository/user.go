package repository

import (
	"context"
	"errors"
	"time"
)

type User struct {
	ID           int64
	Email        string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
}

var ErrUserNotFound = errors.New("repository: user not found")

//go:generate go tool mockgen -destination=../mock/mock_repository/user.go golang-fiber-jwt-auth/repository UserRepository
type UserRepository interface {
	Create(ctx context.Context, user User) (*User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByID(ctx context.Context, id int64) (*User, error)
}
