package test

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	httpadapter "auth-service/adapters/in/http"
	maileradapter "auth-service/adapters/out/mailer"
	"auth-service/core"
	"auth-service/ports"
)

func TestSignupVerifyThenLogin(t *testing.T) {
	repo := newInMemoryUsersRepo()

	var mailerOutput bytes.Buffer
	logger := log.New(&mailerOutput, "", 0)
	loggerMailer := maileradapter.NewLoggerMailer(logger)

	usecases := core.NewAuthUsecases(repo, loggerMailer)
	handlers := httpadapter.NewAuthHandlers(usecases)
	router := httpadapter.NewRouter(handlers)

	signupPayload := map[string]string{
		"email":    "person@example.com",
		"password": "very-secret",
	}
	signupResp := doJSONRequest(t, router, http.MethodPost, "/signup", signupPayload)
	if signupResp.Code != http.StatusOK {
		t.Fatalf("expected signup status %d, got %d", http.StatusOK, signupResp.Code)
	}

	token := extractVerificationToken(t, mailerOutput.String())
	verifyPayload := map[string]string{"token": token}
	verifyResp := doJSONRequest(t, router, http.MethodPost, "/verify-email", verifyPayload)
	if verifyResp.Code != http.StatusOK {
		t.Fatalf("expected verify status %d, got %d", http.StatusOK, verifyResp.Code)
	}

	loginPayload := map[string]string{
		"email":    "person@example.com",
		"password": "very-secret",
	}
	loginResp := doJSONRequest(t, router, http.MethodPost, "/login", loginPayload)
	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected login status %d, got %d", http.StatusOK, loginResp.Code)
	}

	cookies := loginResp.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie to be set")
	}
}

func doJSONRequest(t *testing.T, router http.Handler, method, path string, payload any) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	return rec
}

func extractVerificationToken(t *testing.T, logs string) string {
	t.Helper()

	matches := regexp.MustCompile(`verification_token=([a-zA-Z0-9]+)`).FindStringSubmatch(logs)
	if len(matches) < 2 {
		t.Fatalf("expected verification token in logs, got: %q", logs)
	}

	return matches[1]
}

type inMemoryUsersRepo struct {
	usersByEmail map[string]ports.StoredUser
	tokenToEmail map[string]string
	nextID       int64
}

func newInMemoryUsersRepo() *inMemoryUsersRepo {
	return &inMemoryUsersRepo{
		usersByEmail: map[string]ports.StoredUser{},
		tokenToEmail: map[string]string{},
		nextID:       1,
	}
}

func (r *inMemoryUsersRepo) Create(ctx context.Context, email, passwordHash, verificationToken string) error {
	_ = ctx
	if _, exists := r.usersByEmail[email]; exists {
		return core.ErrUserAlreadyExists
	}

	user := ports.StoredUser{
		ID:            r.nextID,
		Email:         email,
		PasswordHash:  passwordHash,
		EmailVerified: false,
	}
	r.nextID++
	r.usersByEmail[email] = user
	r.tokenToEmail[verificationToken] = email
	return nil
}

func (r *inMemoryUsersRepo) FindByEmail(ctx context.Context, email string) (ports.StoredUser, error) {
	_ = ctx
	user, ok := r.usersByEmail[email]
	if !ok {
		return ports.StoredUser{}, core.ErrInvalidCredentials
	}

	return user, nil
}

func (r *inMemoryUsersRepo) MarkEmailVerified(ctx context.Context, token string) error {
	_ = ctx
	email, ok := r.tokenToEmail[token]
	if !ok {
		return core.ErrInvalidVerificationToken
	}

	user := r.usersByEmail[email]
	user.EmailVerified = true
	r.usersByEmail[email] = user
	delete(r.tokenToEmail, token)
	return nil
}
