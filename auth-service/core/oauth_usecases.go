package core

import (
	"auth-service/ports"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidOAuthRequest = errors.New("invalid oauth request")
	ErrInvalidGrant        = errors.New("invalid grant")
	ErrUnauthorized        = errors.New("unauthorized")
)

type AuthorizationCodeRecord struct {
	Code                string
	UserID              int64
	ClientID            string
	RedirectURI         string
	Scope               string
	Nonce               string
	AuthTime            time.Time
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

type AuthorizationCodeStore interface {
	SaveAuthorizationCode(ctx context.Context, record AuthorizationCodeRecord) error
	ConsumeAuthorizationCode(ctx context.Context, code string) (AuthorizationCodeRecord, error)
}

type TokenSigner interface {
	SignToken(subject, audience string, ttl time.Duration, additionalClaims map[string]any) (string, error)
	ParseAndValidate(token, expectedAudience, expectedTokenUse string) (map[string]any, error)
	JWKS() map[string]any
	Issuer() string
}

type OAuthUsersReader interface {
	FindByID(ctx context.Context, userID int64) (ports.StoredUser, error)
}

type OAuthClientConfig struct {
	ClientID            string
	AllowedRedirectURIs map[string]struct{}
}

type CreateAuthorizationCodeInput struct {
	UserID              int64
	ClientID            string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type ExchangeAuthorizationCodeInput struct {
	Code         string
	ClientID     string
	RedirectURI  string
	CodeVerifier string
}

type TokenSet struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type OAuthUsecases struct {
	codeStore  AuthorizationCodeStore
	users      OAuthUsersReader
	signer     TokenSigner
	clientConf OAuthClientConfig
	now        func() time.Time
}

func NewOAuthUsecases(codeStore AuthorizationCodeStore, users OAuthUsersReader, signer TokenSigner, clientConf OAuthClientConfig) *OAuthUsecases {
	return &OAuthUsecases{
		codeStore:  codeStore,
		users:      users,
		signer:     signer,
		clientConf: clientConf,
		now:        time.Now,
	}
}

func (u *OAuthUsecases) CreateAuthorizationCode(ctx context.Context, input CreateAuthorizationCodeInput) (string, error) {
	if input.UserID <= 0 || strings.TrimSpace(input.ClientID) == "" || strings.TrimSpace(input.RedirectURI) == "" {
		return "", ErrInvalidOAuthRequest
	}
	if input.ClientID != u.clientConf.ClientID {
		return "", ErrUnauthorized
	}
	if _, ok := u.clientConf.AllowedRedirectURIs[input.RedirectURI]; !ok {
		return "", ErrInvalidOAuthRequest
	}
	if strings.TrimSpace(input.CodeChallenge) == "" || strings.TrimSpace(input.CodeChallengeMethod) != "S256" {
		return "", ErrInvalidOAuthRequest
	}

	code, err := randomToken(24)
	if err != nil {
		return "", err
	}

	record := AuthorizationCodeRecord{
		Code:                code,
		UserID:              input.UserID,
		ClientID:            input.ClientID,
		RedirectURI:         input.RedirectURI,
		Scope:               strings.TrimSpace(input.Scope),
		Nonce:               strings.TrimSpace(input.Nonce),
		AuthTime:            u.now().UTC(),
		CodeChallenge:       input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
		ExpiresAt:           u.now().Add(5 * time.Minute),
	}
	if err := u.codeStore.SaveAuthorizationCode(ctx, record); err != nil {
		return "", err
	}

	return code, nil
}

func (u *OAuthUsecases) ExchangeCode(ctx context.Context, input ExchangeAuthorizationCodeInput) (TokenSet, error) {
	if strings.TrimSpace(input.Code) == "" || strings.TrimSpace(input.ClientID) == "" || strings.TrimSpace(input.RedirectURI) == "" || strings.TrimSpace(input.CodeVerifier) == "" {
		return TokenSet{}, ErrInvalidOAuthRequest
	}
	if input.ClientID != u.clientConf.ClientID {
		return TokenSet{}, ErrUnauthorized
	}
	if _, ok := u.clientConf.AllowedRedirectURIs[input.RedirectURI]; !ok {
		return TokenSet{}, ErrInvalidOAuthRequest
	}

	record, err := u.codeStore.ConsumeAuthorizationCode(ctx, input.Code)
	if err != nil {
		return TokenSet{}, ErrInvalidGrant
	}
	if u.now().After(record.ExpiresAt) {
		return TokenSet{}, ErrInvalidGrant
	}
	if record.ClientID != input.ClientID || record.RedirectURI != input.RedirectURI {
		return TokenSet{}, ErrInvalidGrant
	}

	sum := sha256.Sum256([]byte(input.CodeVerifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != record.CodeChallenge {
		return TokenSet{}, ErrInvalidGrant
	}

	userIdentity, err := u.users.FindByID(ctx, record.UserID)
	if err != nil {
		return TokenSet{}, ErrInvalidGrant
	}

	subject := formatUserSubject(record.UserID)
	accessToken, err := u.signer.SignToken(subject, record.ClientID, time.Hour, map[string]any{
		"scope":     record.Scope,
		"token_use": "access",
	})
	if err != nil {
		return TokenSet{}, err
	}
	idClaims := map[string]any{
		"scope":          record.Scope,
		"token_use":      "id",
		"auth_time":      record.AuthTime.Unix(),
		"email":          userIdentity.Email,
		"email_verified": userIdentity.EmailVerified,
	}
	if record.Nonce != "" {
		idClaims["nonce"] = record.Nonce
	}
	idToken, err := u.signer.SignToken(subject, record.ClientID, time.Hour, idClaims)
	if err != nil {
		return TokenSet{}, err
	}
	refreshToken, err := randomToken(32)
	if err != nil {
		return TokenSet{}, err
	}

	return TokenSet{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil
}

func (u *OAuthUsecases) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	_ = ctx
	if strings.TrimSpace(accessToken) == "" {
		return nil, ErrUnauthorized
	}

	claims, err := u.signer.ParseAndValidate(accessToken, u.clientConf.ClientID, "access")
	if err != nil {
		return nil, ErrUnauthorized
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, ErrUnauthorized
	}
	return map[string]any{"sub": sub}, nil
}

func (u *OAuthUsecases) JWKS() map[string]any {
	return u.signer.JWKS()
}

func (u *OAuthUsecases) Issuer() string {
	return u.signer.Issuer()
}

func (u *OAuthUsecases) ConfiguredClientID() string {
	return u.clientConf.ClientID
}

func formatUserSubject(userID int64) string {
	return "user:" + strconv.FormatInt(userID, 10)
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
