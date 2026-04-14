package ports

import "context"

type StoredUser struct {
	ID            int64
	Email         string
	PasswordHash  string
	EmailVerified bool
}

type UsersRepository interface {
	Create(ctx context.Context, email, passwordHash, verificationToken string) error
	FindByEmail(ctx context.Context, email string) (StoredUser, error)
	FindByID(ctx context.Context, userID int64) (StoredUser, error)
	MarkEmailVerified(ctx context.Context, token string) error
}
