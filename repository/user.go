package repository

import (
	"context"
	"errors"
	"time"
)

type User struct {
	ID           int64     `db:"id"`
	Email        string    `db:"email"`
	PasswordHash string    `db:"password_hash"`
	Role         string    `db:"role"`
	CreatedAt    time.Time `db:"created_at"`
}

var ErrUserNotFound = errors.New("repository: user not found")

//go:generate mockgen -destination=../mock/mock_repository/user.go golang-fiber-jwt-auth/repository UserRepository
type UserRepository interface {
	Create(ctx context.Context, user User) (*User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByID(ctx context.Context, id int64) (*User, error)
}
