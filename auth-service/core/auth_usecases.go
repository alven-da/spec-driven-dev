package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"

	"auth-service/ports"
	"golang.org/x/crypto/bcrypt"
)

type AuthUsecases struct {
	usersRepo ports.UsersRepository
	mailer    ports.Mailer
}

func NewAuthUsecases(usersRepo ports.UsersRepository, mailer ports.Mailer) *AuthUsecases {
	return &AuthUsecases{
		usersRepo: usersRepo,
		mailer:    mailer,
	}
}

func (u *AuthUsecases) Signup(ctx context.Context, email, password string) error {
	email = strings.TrimSpace(email)
	if email == "" || password == "" {
		return ErrInvalidInput
	}

	passwordHashBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	verificationToken, err := generateToken(16)
	if err != nil {
		return err
	}

	if err := u.usersRepo.Create(ctx, email, string(passwordHashBytes), verificationToken); err != nil {
		return err
	}

	return u.mailer.SendVerificationEmail(ctx, email, verificationToken)
}

func (u *AuthUsecases) VerifyEmail(ctx context.Context, token string) error {
	if strings.TrimSpace(token) == "" {
		return ErrInvalidInput
	}

	return u.usersRepo.MarkEmailVerified(ctx, token)
}

func (u *AuthUsecases) Login(ctx context.Context, email, password string) (Session, error) {
	email = strings.TrimSpace(email)
	if email == "" || password == "" {
		return Session{}, ErrInvalidInput
	}

	user, err := u.usersRepo.FindByEmail(ctx, email)
	if err != nil {
		return Session{}, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return Session{}, ErrInvalidCredentials
	}

	if !user.EmailVerified {
		return Session{}, ErrEmailNotVerified
	}

	return Session{
		UserID: user.ID,
		Email:  user.Email,
	}, nil
}

func generateToken(bytesSize int) (string, error) {
	buf := make([]byte, bytesSize)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil
}
