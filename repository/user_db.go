package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"
)

type userRepositoryDB struct {
	db *sqlx.DB
}

func NewUserRepositoryDB(db *sqlx.DB) UserRepository {
	return userRepositoryDB{db: db}
}

func (r userRepositoryDB) Create(ctx context.Context, user User) (*User, error) {
	const query = `
		INSERT INTO users (email, password_hash, role)
		VALUES ($1, $2, $3)
		RETURNING id, email, password_hash, role, created_at
	`

	var created User
	err := r.db.QueryRowxContext(ctx, query, user.Email, user.PasswordHash, user.Role).
		StructScan(&created)
	if err != nil {
		return nil, err
	}

	return &created, nil
}

func (r userRepositoryDB) FindByEmail(ctx context.Context, email string) (*User, error) {
	const query = `
		SELECT id, email, password_hash, role, created_at
		FROM users
		WHERE email = $1
	`

	var user User
	err := r.db.GetContext(ctx, &user, query, email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r userRepositoryDB) FindByID(ctx context.Context, id int64) (*User, error) {
	const query = `
		SELECT id, email, password_hash, role, created_at
		FROM users
		WHERE id = $1
	`

	var user User
	err := r.db.GetContext(ctx, &user, query, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	return &user, nil
}
