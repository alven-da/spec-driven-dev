package postgres

import (
	"context"
	"database/sql"
	"errors"

	"auth-service/core"
)

type OAuthRepo struct {
	db *sql.DB
}

func NewOAuthRepo(db *sql.DB) *OAuthRepo {
	return &OAuthRepo{db: db}
}

func (r *OAuthRepo) SaveAuthorizationCode(ctx context.Context, record core.AuthorizationCodeRecord) error {
	_, err := r.db.ExecContext(
		ctx,
		`INSERT INTO oauth_authorization_codes
		 (code, user_id, client_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		record.Code,
		record.UserID,
		record.ClientID,
		record.RedirectURI,
		record.Scope,
		record.CodeChallenge,
		record.CodeChallengeMethod,
		record.ExpiresAt,
	)
	return err
}

func (r *OAuthRepo) ConsumeAuthorizationCode(ctx context.Context, code string) (core.AuthorizationCodeRecord, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return core.AuthorizationCodeRecord{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var record core.AuthorizationCodeRecord
	err = tx.QueryRowContext(
		ctx,
		`SELECT code, user_id, client_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at
		 FROM oauth_authorization_codes
		 WHERE code = $1
		 FOR UPDATE`,
		code,
	).Scan(
		&record.Code,
		&record.UserID,
		&record.ClientID,
		&record.RedirectURI,
		&record.Scope,
		&record.CodeChallenge,
		&record.CodeChallengeMethod,
		&record.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return core.AuthorizationCodeRecord{}, core.ErrInvalidGrant
		}
		return core.AuthorizationCodeRecord{}, err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM oauth_authorization_codes WHERE code = $1`, code); err != nil {
		return core.AuthorizationCodeRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return core.AuthorizationCodeRecord{}, err
	}

	return record, nil
}
