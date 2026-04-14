package core

import "errors"

var (
	ErrInvalidCredentials       = errors.New("invalid credentials")
	ErrEmailNotVerified         = errors.New("email is not verified")
	ErrInvalidVerificationToken = errors.New("invalid verification token")
	ErrUserAlreadyExists        = errors.New("user already exists")
	ErrInvalidInput             = errors.New("invalid input")
)

type Session struct {
	UserID int64
	Email  string
}
