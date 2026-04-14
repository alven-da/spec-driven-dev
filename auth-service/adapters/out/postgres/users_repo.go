package postgres

import (
	"context"
	"database/sql"
	"errors"

	"auth-service/core"
	"auth-service/ports"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type UsersRepo struct {
	db *sql.DB
}

func NewUsersRepo(db *sql.DB) *UsersRepo {
	return &UsersRepo{db: db}
}

func (r *UsersRepo) Create(ctx context.Context, email, passwordHash, verificationToken string) error {
	_, err := r.db.ExecContext(
		ctx,
		`INSERT INTO users (email, password_hash, email_verified, verification_token)
		 VALUES ($1, $2, FALSE, $3)`,
		email,
		passwordHash,
		verificationToken,
	)
	if err != nil {
		return err
	}

	return nil
}

func (r *UsersRepo) FindByEmail(ctx context.Context, email string) (ports.StoredUser, error) {
	var user ports.StoredUser
	err := r.db.QueryRowContext(
		ctx,
		`SELECT id, email, password_hash, email_verified
		 FROM users
		 WHERE email = $1`,
		email,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.EmailVerified)
	if err != nil {
		return ports.StoredUser{}, err
	}

	return user, nil
}

func (r *UsersRepo) MarkEmailVerified(ctx context.Context, token string) error {
	result, err := r.db.ExecContext(
		ctx,
		`UPDATE users
		 SET email_verified = TRUE, verification_token = NULL
		 WHERE verification_token = $1 AND email_verified = FALSE`,
		token,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return core.ErrInvalidVerificationToken
	}

	return nil
}

func OpenDB(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}

func IsNotFound(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}
