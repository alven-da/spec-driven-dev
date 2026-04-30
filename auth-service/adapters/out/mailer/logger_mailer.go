package mailer

import (
	"context"
	"log"
)

type LoggerMailer struct {
	logger *log.Logger
}

func NewLoggerMailer(logger *log.Logger) *LoggerMailer {
	return &LoggerMailer{logger: logger}
}

func (m *LoggerMailer) SendVerificationEmail(ctx context.Context, email, token string) error {
	_ = ctx
	m.logger.Printf("email=%s verification_token=%s", email, token)
	return nil
}
