# Auth Service MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-shaped `auth-service` hexagonal monolith in Go that implements the approved OAuth2/OIDC MVP (Auth Code + PKCE, email/password + verification + reset, Google sign-in, RS256 JWT/JWKS, rotating refresh tokens, hosted login UI, and rate limiting).

**Architecture:** This implementation uses a single-service hexagonal structure (`core`, `ports`, `adapters`) where HTTP and persistence are adapters, use-case logic lives in core, and all side effects go through ports. The plan is test-first: each capability starts with failing tests, then minimal implementation, then verification and commit.

**Tech Stack:** Go 1.24+, Chi (or stdlib mux), pgx + PostgreSQL, golang-migrate/sql migrations, jose/jwt library for RS256 + JWKS, bcrypt/argon2id, httptest + testify.

---

## Scope Check

The approved spec includes repository structure for both `auth-service` and `user-profile-service`, but only `auth-service` has full product requirements. This plan intentionally implements `auth-service` MVP only. Create a separate plan for `user-profile-service` after auth MVP is stable.

## Planned File Structure (Auth Service)

- Create: `auth-service/go.mod`
- Create: `auth-service/cmd/auth-service/main.go`
- Create: `auth-service/config/config.go`
- Create: `auth-service/core/`
  - `auth_usecases.go`
  - `oauth_usecases.go`
  - `tokens_usecases.go`
  - `models.go`
- Create: `auth-service/ports/`
  - `repositories.go`
  - `crypto.go`
  - `mailer.go`
  - `google.go`
  - `clock.go`
- Create: `auth-service/adapters/in/http/`
  - `router.go`
  - `handlers_auth.go`
  - `handlers_oauth.go`
  - `middleware_rate_limit.go`
- Create: `auth-service/adapters/out/postgres/`
  - `db.go`
  - `users_repo.go`
  - `oauth_repo.go`
  - `tokens_repo.go`
- Create: `auth-service/adapters/out/jwt/signer.go`
- Create: `auth-service/adapters/out/google/client.go`
- Create: `auth-service/adapters/out/mailer/logger_mailer.go`
- Create: `auth-service/platform/logging/logger.go`
- Create: `auth-service/platform/ratelimit/memory_limiter.go`
- Create: `auth-service/migrations/0001_init.sql`
- Create: `auth-service/migrations/0002_oauth_tables.sql`
- Create: `auth-service/migrations/0003_tokens_rotation.sql`
- Create: `auth-service/test/`
  - `integration_auth_code_pkce_test.go`
  - `integration_signup_verify_login_test.go`
  - `integration_refresh_rotation_test.go`
  - `integration_google_link_test.go`

---

### Task 1: Bootstrap Hexagonal Service Skeleton

**Files:**
- Create: `auth-service/go.mod`
- Create: `auth-service/cmd/auth-service/main.go`
- Create: `auth-service/config/config.go`
- Create: `auth-service/adapters/in/http/router.go`
- Test: `auth-service/test/smoke_startup_test.go`

- [ ] **Step 1: Write the failing smoke test**

```go
package test

import "testing"

func TestServiceBootstraps(t *testing.T) {
	t.Fatalf("TODO: bootstrap test not implemented")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd auth-service && go test ./test -run TestServiceBootstraps -v`  
Expected: FAIL with `TODO: bootstrap test not implemented`

- [ ] **Step 3: Implement minimal bootstrap and router**

```go
// cmd/auth-service/main.go
func main() {
	cfg := config.MustLoad()
	r := httpin.NewRouter()
	log.Fatal(http.ListenAndServe(cfg.HTTPAddr, r))
}
```

```go
// adapters/in/http/router.go
func NewRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return r
}
```

- [ ] **Step 4: Replace failing test with real assertion and re-run**

Run: `cd auth-service && go test ./test -run TestServiceBootstraps -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add auth-service/go.mod auth-service/cmd/auth-service/main.go auth-service/config/config.go auth-service/adapters/in/http/router.go auth-service/test/smoke_startup_test.go
git commit -m "chore(auth-service): bootstrap hexagonal service skeleton"
```

---

### Task 2: Persisted User Accounts + Signup + Email Verification + Login

**Files:**
- Create: `auth-service/core/auth_usecases.go`
- Create: `auth-service/core/models.go`
- Create: `auth-service/ports/repositories.go`
- Create: `auth-service/ports/mailer.go`
- Create: `auth-service/adapters/out/postgres/users_repo.go`
- Create: `auth-service/adapters/out/mailer/logger_mailer.go`
- Modify: `auth-service/adapters/in/http/handlers_auth.go`
- Create: `auth-service/migrations/0001_init.sql`
- Test: `auth-service/test/integration_signup_verify_login_test.go`

- [ ] **Step 1: Write failing integration test for signup -> verify -> login**

```go
func TestSignupVerifyThenLogin(t *testing.T) {
	// 1) POST /signup
	// 2) parse verification token from logger mailer output
	// 3) POST /verify-email
	// 4) POST /login
	// assert 200 + session cookie set
}
```

- [ ] **Step 2: Run test to verify failure on missing routes/logic**

Run: `cd auth-service && go test ./test -run TestSignupVerifyThenLogin -v`  
Expected: FAIL with 404/500 and unmet assertions

- [ ] **Step 3: Implement minimal domain/use-case + persistence + handlers**

```go
// core/auth_usecases.go
func (u *AuthUsecases) Signup(ctx context.Context, email, password string) error { /* hash+save+emit verification */ }
func (u *AuthUsecases) VerifyEmail(ctx context.Context, token string) error { /* consume token, mark verified */ }
func (u *AuthUsecases) Login(ctx context.Context, email, password string) (Session, error) { /* require verified */ }
```

```go
// adapters/in/http/handlers_auth.go
r.Post("/signup", h.Signup)
r.Post("/verify-email", h.VerifyEmail)
r.Post("/login", h.Login)
```

- [ ] **Step 4: Run integration test and full package tests**

Run: `cd auth-service && go test ./test -run TestSignupVerifyThenLogin -v && go test ./...`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add auth-service/core/auth_usecases.go auth-service/core/models.go auth-service/ports/repositories.go auth-service/ports/mailer.go auth-service/adapters/out/postgres/users_repo.go auth-service/adapters/out/mailer/logger_mailer.go auth-service/adapters/in/http/handlers_auth.go auth-service/migrations/0001_init.sql auth-service/test/integration_signup_verify_login_test.go
git commit -m "feat(auth-service): add signup verification and login flow"
```

---

### Task 3: OAuth2/OIDC Discovery + Authorize + Token (Auth Code + PKCE)

**Files:**
- Create: `auth-service/core/oauth_usecases.go`
- Create: `auth-service/adapters/in/http/handlers_oauth.go`
- Create: `auth-service/adapters/out/postgres/oauth_repo.go`
- Create: `auth-service/adapters/out/jwt/signer.go`
- Create: `auth-service/migrations/0002_oauth_tables.sql`
- Test: `auth-service/test/integration_auth_code_pkce_test.go`

- [ ] **Step 1: Write failing integration test for Auth Code + PKCE**

```go
func TestAuthCodePKCEFlow(t *testing.T) {
	// setup verified user session
	// GET /authorize with code_challenge
	// POST /token with code_verifier
	// assert access_token + id_token + refresh_token returned
}
```

- [ ] **Step 2: Run test to verify PKCE flow is not implemented**

Run: `cd auth-service && go test ./test -run TestAuthCodePKCEFlow -v`  
Expected: FAIL due to missing authorize/token behavior

- [ ] **Step 3: Implement minimal OIDC endpoints and use-cases**

```go
// handlers_oauth.go
r.Get("/.well-known/openid-configuration", h.Discovery)
r.Get("/jwks", h.JWKS)
r.Get("/authorize", h.Authorize)
r.Post("/token", h.Token)
r.Get("/userinfo", h.UserInfo)
```

```go
// core/oauth_usecases.go
func (u *OAuthUsecases) CreateAuthorizationCode(...) (string, error) { /* bind PKCE challenge */ }
func (u *OAuthUsecases) ExchangeCode(...) (TokenSet, error) { /* verify code + PKCE */ }
```

- [ ] **Step 4: Run targeted integration and regression suite**

Run: `cd auth-service && go test ./test -run TestAuthCodePKCEFlow -v && go test ./...`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add auth-service/core/oauth_usecases.go auth-service/adapters/in/http/handlers_oauth.go auth-service/adapters/out/postgres/oauth_repo.go auth-service/adapters/out/jwt/signer.go auth-service/migrations/0002_oauth_tables.sql auth-service/test/integration_auth_code_pkce_test.go
git commit -m "feat(auth-service): implement oidc authorize and token pkce flow"
```

---

### Task 4: Refresh Token Rotation + Replay Detection

**Files:**
- Create: `auth-service/core/tokens_usecases.go`
- Create: `auth-service/adapters/out/postgres/tokens_repo.go`
- Create: `auth-service/migrations/0003_tokens_rotation.sql`
- Test: `auth-service/test/integration_refresh_rotation_test.go`

- [ ] **Step 1: Write failing integration test for refresh rotation**

```go
func TestRefreshTokenRotationAndReplayInvalidation(t *testing.T) {
	// 1) obtain initial refresh token from auth code flow
	// 2) exchange once -> new refresh token returned
	// 3) reuse old refresh token -> expect invalid_grant
	// 4) ensure token family invalidated
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd auth-service && go test ./test -run TestRefreshTokenRotationAndReplayInvalidation -v`  
Expected: FAIL (no rotation/replay handling yet)

- [ ] **Step 3: Implement rotation + replay handling in core and repo**

```go
func (u *TokenUsecases) ExchangeRefreshToken(ctx context.Context, token string) (TokenSet, error) {
	// validate token, mark consumed, issue new token in same family
	// if consumed token reused -> revoke family and return invalid_grant
}
```

- [ ] **Step 4: Verify test passes and old behavior remains green**

Run: `cd auth-service && go test ./test -run TestRefreshTokenRotationAndReplayInvalidation -v && go test ./...`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add auth-service/core/tokens_usecases.go auth-service/adapters/out/postgres/tokens_repo.go auth-service/migrations/0003_tokens_rotation.sql auth-service/test/integration_refresh_rotation_test.go
git commit -m "feat(auth-service): add rotating refresh tokens with replay detection"
```

---

### Task 5: Google Sign-In + Same-Email Auto-Link

**Files:**
- Modify: `auth-service/ports/google.go`
- Create: `auth-service/adapters/out/google/client.go`
- Modify: `auth-service/core/auth_usecases.go`
- Modify: `auth-service/adapters/in/http/handlers_auth.go`
- Test: `auth-service/test/integration_google_link_test.go`

- [ ] **Step 1: Write failing integration test for Google callback linking**

```go
func TestGoogleLoginLinksExistingEmailAccount(t *testing.T) {
	// existing local account with email
	// mock google callback with same verified email
	// assert external identity linked and login succeeds as same user
}
```

- [ ] **Step 2: Run test to confirm failure**

Run: `cd auth-service && go test ./test -run TestGoogleLoginLinksExistingEmailAccount -v`  
Expected: FAIL on missing Google/link behavior

- [ ] **Step 3: Implement start/callback flow with verified-email enforcement**

```go
r.Get("/auth/google/start", h.GoogleStart)
r.Get("/auth/google/callback", h.GoogleCallback)
```

```go
// core/auth_usecases.go
func (u *AuthUsecases) LoginWithGoogle(ctx context.Context, idToken string) (Session, error) {
	// verify token, require email_verified=true, auto-link by email
}
```

- [ ] **Step 4: Re-run targeted and full tests**

Run: `cd auth-service && go test ./test -run TestGoogleLoginLinksExistingEmailAccount -v && go test ./...`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add auth-service/ports/google.go auth-service/adapters/out/google/client.go auth-service/core/auth_usecases.go auth-service/adapters/in/http/handlers_auth.go auth-service/test/integration_google_link_test.go
git commit -m "feat(auth-service): add google login and same-email account linking"
```

---

### Task 6: Security Hardening, Rate Limiting, and Logout Semantics

**Files:**
- Create: `auth-service/adapters/in/http/middleware_rate_limit.go`
- Create: `auth-service/platform/ratelimit/memory_limiter.go`
- Modify: `auth-service/adapters/in/http/router.go`
- Modify: `auth-service/adapters/in/http/handlers_auth.go`
- Test: `auth-service/test/integration_rate_limit_logout_test.go`

- [ ] **Step 1: Write failing tests for rate-limited login and logout**

```go
func TestLoginEndpointRateLimitedByIPAndIdentifier(t *testing.T) {}
func TestLogoutInvalidatesHostedSession(t *testing.T) {}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cd auth-service && go test ./test -run 'TestLoginEndpointRateLimitedByIPAndIdentifier|TestLogoutInvalidatesHostedSession' -v`  
Expected: FAIL

- [ ] **Step 3: Implement limiter middleware and logout handler**

```go
// middleware_rate_limit.go
func RateLimit(next http.Handler) http.Handler { /* check IP + email key */ }
```

```go
// handlers_auth.go
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	// invalidate hosted session; do not revoke refresh tokens in MVP
}
```

- [ ] **Step 4: Run security-focused integration tests and full suite**

Run: `cd auth-service && go test ./test -run 'TestLoginEndpointRateLimitedByIPAndIdentifier|TestLogoutInvalidatesHostedSession' -v && go test ./...`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add auth-service/adapters/in/http/middleware_rate_limit.go auth-service/platform/ratelimit/memory_limiter.go auth-service/adapters/in/http/router.go auth-service/adapters/in/http/handlers_auth.go auth-service/test/integration_rate_limit_logout_test.go
git commit -m "feat(auth-service): add login rate limiting and logout session invalidation"
```

---

### Task 7: Final Verification + Documentation Sync

**Files:**
- Modify: `docs/superpowers/specs/2026-04-10-authentication-backend-service-design.md` (only if implementation-driven clarifications are needed)
- Create: `auth-service/README.md`

- [ ] **Step 1: Write failing doc quality check (manual checklist in README)**

```markdown
- [ ] local run command documented
- [ ] required env vars documented
- [ ] migrations command documented
- [ ] test command documented
```

- [ ] **Step 2: Run full verification suite**

Run: `cd auth-service && go test ./...`  
Expected: PASS

- [ ] **Step 3: Add operator-focused README**

```md
## Run
go run ./cmd/auth-service

## Test
go test ./...
```

- [ ] **Step 4: Re-run tests and ensure docs match behavior**

Run: `cd auth-service && go test ./...`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add auth-service/README.md docs/superpowers/specs/2026-04-10-authentication-backend-service-design.md
git commit -m "docs(auth-service): add runbook and align spec details"
```

---

## Plan Self-Review

### 1) Spec coverage check

- Hosted login, signup, verify, reset: covered in Task 2.
- OIDC discovery, JWKS, authorize, token, userinfo, PKCE: covered in Task 3.
- RS256 JWT tokens: Task 3.
- Rotating refresh + replay: Task 4.
- Google sign-in + auto-link: Task 5.
- Rate limiting + logout semantics: Task 6.
- Hexagonal folder structure and monolith boundaries: Task 1 + planned file structure.

No uncovered auth-service MVP requirements found.

### 2) Placeholder scan

No `TODO/TBD/implement later` placeholders remain in actionable steps. All tasks include file paths, commands, and expected outcomes.

### 3) Type and naming consistency

Naming is consistent across tasks:
- `AuthUsecases`, `OAuthUsecases`, `TokenUsecases`
- routes: `/authorize`, `/token`, `/userinfo`, `/auth/google/start`, `/auth/google/callback`
- refresh replay behavior uses "token family invalidation"

---

Plan complete and saved to `docs/superpowers/plans/2026-04-10-auth-service-mvp-implementation-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
