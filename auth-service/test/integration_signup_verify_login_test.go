package test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	httpadapter "auth-service/adapters/in/http"
	jwtadapter "auth-service/adapters/out/jwt"
	maileradapter "auth-service/adapters/out/mailer"
	"auth-service/core"
	"auth-service/ports"
)

func TestSignupVerifyThenLogin(t *testing.T) {
	router, mailerOutput := newTestAuthRouter(false, true)

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
	if cookies[0].Name != "auth_session" {
		t.Fatalf("expected cookie name %q, got %q", "auth_session", cookies[0].Name)
	}
	if !cookies[0].HttpOnly {
		t.Fatal("expected auth_session cookie to be HttpOnly")
	}
	if cookies[0].Path != "/" {
		t.Fatalf("expected cookie path %q, got %q", "/", cookies[0].Path)
	}
	if !cookies[0].Secure {
		t.Fatal("expected auth_session cookie to be Secure")
	}
}

func TestSignupDuplicateEmailReturnsConflict(t *testing.T) {
	router, _ := newTestAuthRouter(false, true)

	payload := map[string]string{
		"email":    "dupe@example.com",
		"password": "secret",
	}
	firstResp := doJSONRequest(t, router, http.MethodPost, "/signup", payload)
	if firstResp.Code != http.StatusOK {
		t.Fatalf("expected first signup status %d, got %d", http.StatusOK, firstResp.Code)
	}

	secondResp := doJSONRequest(t, router, http.MethodPost, "/signup", payload)
	if secondResp.Code != http.StatusConflict {
		t.Fatalf("expected duplicate signup status %d, got %d", http.StatusConflict, secondResp.Code)
	}
}

func TestVerifyEmailInvalidTokenReturnsBadRequest(t *testing.T) {
	router, _ := newTestAuthRouter(false, true)

	verifyResp := doJSONRequest(t, router, http.MethodPost, "/verify-email", map[string]string{"token": "missing"})
	if verifyResp.Code != http.StatusBadRequest {
		t.Fatalf("expected verify invalid token status %d, got %d", http.StatusBadRequest, verifyResp.Code)
	}
}

func TestLoginBeforeVerificationReturnsForbidden(t *testing.T) {
	router, _ := newTestAuthRouter(false, true)

	payload := map[string]string{
		"email":    "pending@example.com",
		"password": "secret",
	}
	signupResp := doJSONRequest(t, router, http.MethodPost, "/signup", payload)
	if signupResp.Code != http.StatusOK {
		t.Fatalf("expected signup status %d, got %d", http.StatusOK, signupResp.Code)
	}

	loginResp := doJSONRequest(t, router, http.MethodPost, "/login", payload)
	if loginResp.Code != http.StatusForbidden {
		t.Fatalf("expected pre-verification login status %d, got %d", http.StatusForbidden, loginResp.Code)
	}
}

func TestLoginWrongPasswordReturnsUnauthorized(t *testing.T) {
	router, mailerOutput := newTestAuthRouter(false, true)

	signupPayload := map[string]string{
		"email":    "verify-first@example.com",
		"password": "correct-password",
	}
	signupResp := doJSONRequest(t, router, http.MethodPost, "/signup", signupPayload)
	if signupResp.Code != http.StatusOK {
		t.Fatalf("expected signup status %d, got %d", http.StatusOK, signupResp.Code)
	}

	token := extractVerificationToken(t, mailerOutput.String())
	verifyResp := doJSONRequest(t, router, http.MethodPost, "/verify-email", map[string]string{"token": token})
	if verifyResp.Code != http.StatusOK {
		t.Fatalf("expected verify status %d, got %d", http.StatusOK, verifyResp.Code)
	}

	loginResp := doJSONRequest(t, router, http.MethodPost, "/login", map[string]string{
		"email":    "verify-first@example.com",
		"password": "wrong-password",
	})
	if loginResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected wrong-password login status %d, got %d", http.StatusUnauthorized, loginResp.Code)
	}
}

func TestSignupSucceedsWhenMailerFails(t *testing.T) {
	router, _ := newTestAuthRouter(true, true)

	signupResp := doJSONRequest(t, router, http.MethodPost, "/signup", map[string]string{
		"email":    "mail-failure@example.com",
		"password": "secret",
	})
	if signupResp.Code != http.StatusOK {
		t.Fatalf("expected signup status %d despite mailer failure, got %d", http.StatusOK, signupResp.Code)
	}
}

func TestLoginCookieSecureDisabledForLocalMode(t *testing.T) {
	router, mailerOutput := newTestAuthRouter(false, false)

	signupPayload := map[string]string{
		"email":    "local@example.com",
		"password": "very-secret",
	}
	signupResp := doJSONRequest(t, router, http.MethodPost, "/signup", signupPayload)
	if signupResp.Code != http.StatusOK {
		t.Fatalf("expected signup status %d, got %d", http.StatusOK, signupResp.Code)
	}

	token := extractVerificationToken(t, mailerOutput.String())
	verifyResp := doJSONRequest(t, router, http.MethodPost, "/verify-email", map[string]string{"token": token})
	if verifyResp.Code != http.StatusOK {
		t.Fatalf("expected verify status %d, got %d", http.StatusOK, verifyResp.Code)
	}

	loginResp := doJSONRequest(t, router, http.MethodPost, "/login", signupPayload)
	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected login status %d, got %d", http.StatusOK, loginResp.Code)
	}

	cookies := loginResp.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie to be set")
	}
	if cookies[0].Secure {
		t.Fatal("expected auth_session cookie Secure=false for local mode")
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

type errMailer struct{}

func (m *errMailer) SendVerificationEmail(ctx context.Context, email, token string) error {
	_ = ctx
	_ = email
	_ = token
	return errors.New("mailer unavailable")
}

func newTestAuthRouter(useFailingMailer bool, secureCookie bool) (http.Handler, *bytes.Buffer) {
	repo := newInMemoryUsersRepo()
	oauthRepo := newInMemoryOAuthRepo()

	var mailerOutput bytes.Buffer
	logger := log.New(&mailerOutput, "", 0)

	var mailer ports.Mailer = maileradapter.NewLoggerMailer(logger)
	if useFailingMailer {
		mailer = &errMailer{}
	}

	usecases := core.NewAuthUsecases(repo, mailer)
	handlers := httpadapter.NewAuthHandlers(usecases, secureCookie)

	signer, err := jwtadapter.NewSigner("http://issuer.test")
	if err != nil {
		panic(err)
	}
	oauthUsecases := core.NewOAuthUsecases(oauthRepo, signer)
	oauthHandlers := httpadapter.NewOAuthHandlers(oauthUsecases)
	router := httpadapter.NewRouter(handlers, oauthHandlers)

	return router, &mailerOutput
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

type inMemoryOAuthRepo struct {
	records map[string]core.AuthorizationCodeRecord
}

func newInMemoryOAuthRepo() *inMemoryOAuthRepo {
	return &inMemoryOAuthRepo{
		records: map[string]core.AuthorizationCodeRecord{},
	}
}

func (r *inMemoryOAuthRepo) SaveAuthorizationCode(ctx context.Context, record core.AuthorizationCodeRecord) error {
	_ = ctx
	r.records[record.Code] = record
	return nil
}

func (r *inMemoryOAuthRepo) ConsumeAuthorizationCode(ctx context.Context, code string) (core.AuthorizationCodeRecord, error) {
	_ = ctx
	record, ok := r.records[code]
	if !ok {
		return core.AuthorizationCodeRecord{}, core.ErrInvalidGrant
	}

	if time.Now().After(record.ExpiresAt) {
		return core.AuthorizationCodeRecord{}, core.ErrInvalidGrant
	}

	delete(r.records, code)
	return record, nil
}
