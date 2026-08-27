package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type userRow struct {
	ID           int64
	Email        string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
}

func (userRow) TableName() string {
	return "users"
}

type userRepositoryDB struct {
	db *gorm.DB
}

func NewUserRepositoryDB(db *gorm.DB) UserRepository {
	return userRepositoryDB{db: db}
}

func (r userRepositoryDB) Create(ctx context.Context, user User) (*User, error) {
	row := toUserRow(user)

	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	created := toUserDomain(row)
	return &created, nil
}

func (r userRepositoryDB) FindByEmail(ctx context.Context, email string) (*User, error) {
	var row userRow
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user by email: %w", err)
	}

	user := toUserDomain(row)
	return &user, nil
}

func (r userRepositoryDB) FindByID(ctx context.Context, id int64) (*User, error) {
	var row userRow
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user by id: %w", err)
	}

	user := toUserDomain(row)
	return &user, nil
}

func toUserRow(user User) userRow {
	return userRow{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		Role:         user.Role,
		CreatedAt:    user.CreatedAt,
	}
}

func toUserDomain(row userRow) User {
	return User{
		ID:           row.ID,
		Email:        row.Email,
		PasswordHash: row.PasswordHash,
		Role:         row.Role,
		CreatedAt:    row.CreatedAt,
	}
}
