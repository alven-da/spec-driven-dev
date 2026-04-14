package ports

import "context"

type Mailer interface {
	SendVerificationEmail(ctx context.Context, email, token string) error
}
