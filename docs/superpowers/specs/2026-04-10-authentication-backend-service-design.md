# Authentication Backend Service Design

## Summary

Build a Go-based OAuth2/OIDC identity provider for first-party web and mobile clients as a modular monolith. The MVP provides a hosted login UI, email/password authentication with mandatory email verification, Google social login, JWT-based OIDC tokens, rotating refresh tokens, and PostgreSQL-backed persistence.

## Goals

- Support first-party web and mobile authentication through Authorization Code + PKCE.
- Provide a hosted authentication experience owned by the service.
- Issue OIDC-compatible access and ID tokens signed with RS256.
- Support email/password signup and login with mandatory email verification.
- Support Google social login in the MVP.
- Keep the MVP intentionally narrow by targeting a single OAuth client configured through environment or config files.
- Keep authentication implementation and deployment monolithic: one auth service process and one auth database, even when the repository later contains additional services.

## Non-Goals

- Multi-factor authentication in the MVP.
- Multi-tenant client registration or self-service app onboarding.
- Multiple OAuth clients in the MVP.
- RP-initiated logout in the MVP.
- Refresh token revocation as part of logout in the MVP.
- Production email delivery integration in the MVP.

## Recommended Implementation Approach

Use a thin-domain hybrid design:

- Implement the HTTP endpoints and core domain rules explicitly in Go.
- Use established libraries for password hashing, JWT signing, JWKS publishing, SQL access, and Google token validation.
- Keep security-critical state transitions visible in application code and covered by focused tests.

This approach balances control and learning value with lower risk than a fully hand-rolled cryptographic or protocol implementation.

## Repository and Deployment Approach

Use a monolithic approach:

- The repository may host multiple services over time.
- The authentication service lives in its own top-level folder and is developed as a modular monolith.
- Additional services should follow the same modular monolith architecture style for consistency.
- The auth runtime is one deployable Go service process.
- The auth runtime owns one PostgreSQL database schema or database.
- Modular internal packages keep boundaries clear (HTTP, domain, persistence, crypto, integrations), but auth is not split into microservices.

Suggested top-level layout:

- `auth-service/`
  - `cmd/auth-service/` for composition root and process bootstrap.
  - `core/` for use-case logic and core business rules.
  - `ports/` for inbound and outbound interfaces.
  - `adapters/`
    - `in/http/` for HTTP handlers, routing, middleware, validation, and auth UI delivery.
    - `out/postgres/` for persistence adapters.
    - `out/google/` for Google identity adapter.
    - `out/mailer/` for email adapter (log-only in dev, pluggable in prod).
    - `out/jwt/` for token signing and verification.
  - `config/` for typed configuration and bootstrap validation.
  - `platform/` for cross-cutting concerns (logging, rate limiting, clock, id generation).
  - `migrations/` for database schema evolution.
  - `test/` for end-to-end and integration suites.

Architectural rules for both services:

- Dependencies flow inward: adapters -> ports -> core.
- Core layer has no dependency on framework, transport, or database code.
- Core coordinates use cases and business rules through ports.
- Outbound side effects occur only through outbound ports implemented by adapters.
- Shared code should be minimal and explicit to avoid accidental coupling between services.

## MVP Scope

### Included

- Hosted login and signup UI.
- Email/password signup and login.
- Required email verification before a user may complete login or authorization.
- Password reset through an emailed reset link or token.
- Google social login.
- Automatic linking of Google login to an existing local account when Google proves ownership of the same email address.
- OIDC discovery and JWKS publishing.
- Authorization Code flow with PKCE.
- JWT access tokens signed with RS256.
- ID tokens signed with RS256.
- Rotating refresh tokens with replay detection.
- Rate limiting on sensitive auth endpoints.
- PostgreSQL as the system of record.
- Log-only email delivery for development.

### Deferred

- TOTP or SMS-based MFA.
- More than one OAuth client.
- Client credentials or device authorization grants.
- Apple, GitHub, Microsoft, or enterprise SSO providers.
- Production email provider integration.
- Automated signing key rotation.
- User-managed session revocation and token management UI.

## High-Level Architecture

The system is a modular monolith delivered as a single deployable Go application:

1. HTTP layer for OIDC endpoints and hosted auth pages.
2. Domain services for users, sessions, OAuth2/OIDC flow state, token issuance, and external identity linking.
3. Crypto and key management for password hashing, JWT signing, and JWKS publishing.
4. PostgreSQL persistence for durable auth state.
5. Configuration layer for the single OAuth client, Google OAuth credentials, and runtime secrets.

## Components

### HTTP Endpoints

- `GET /.well-known/openid-configuration`
- `GET /jwks`
- `GET /authorize`
- `POST /token`
- `GET /userinfo`
- `GET /login`
- `POST /login`
- `GET /signup`
- `POST /signup`
- `GET /verify-email`
- `POST /verify-email`
- `GET /forgot-password`
- `POST /forgot-password`
- `GET /reset-password`
- `POST /reset-password`
- `GET /auth/google/start`
- `GET /auth/google/callback`
- `POST /logout` or `GET /logout`

### Domain Modules

- **User service**
  - Create and fetch users.
  - Manage verified and unverified account state.
  - Set password hashes.
  - Handle password reset completion.
- **Session service**
  - Create, validate, and destroy hosted IdP sessions.
  - Back the authenticated browser session used by `/authorize`.
- **OAuth2/OIDC service**
  - Create authorization codes.
  - Verify PKCE.
  - Mint access and ID tokens.
  - Rotate refresh tokens and detect replay.
- **External identity service**
  - Validate Google identity data.
  - Auto-link or create accounts.
- **Mailer interface**
  - Emit verification and reset messages.
  - Use a log sink in development and remain replaceable in production.

## Primary Flows

### Authorization Code + PKCE

1. The client redirects the user to `GET /authorize` with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, and PKCE parameters.
2. If the user lacks a valid IdP session, the service redirects them to the hosted login page.
3. After successful login and email verification checks, the service creates a short-lived, one-time authorization code bound to:
   - user ID
   - client ID
   - redirect URI
   - requested scopes
   - PKCE challenge and method
4. The service redirects back to the client with the authorization code.
5. The client calls `POST /token` with the authorization code and `code_verifier`.
6. The service verifies the code, redirect URI, client, and PKCE inputs, then returns:
   - access token
   - ID token
   - refresh token

### Email/Password Signup

1. A user submits the signup form.
2. The service creates a user in an unverified state and stores a password hash.
3. The service issues an email verification token.
4. In development, the verification email content is logged.
5. The user cannot complete login or authorization until verification succeeds.

### Email Verification

1. The user follows a verification link or submits a token/code.
2. The service validates token integrity, expiry, and one-time-use status.
3. The user record becomes verified.

### Password Reset

1. A user submits the forgot-password form.
2. The service generates a password reset token if the account exists, without exposing account existence.
3. In development, the reset message is logged.
4. The user submits a new password through the reset flow.
5. The service validates and consumes the reset token, then updates the stored password hash.

### Google Sign-In

1. The user starts the Google sign-in flow from the hosted login page.
2. After Google redirects back, the service validates the upstream identity assertions.
3. The service requires `email_verified=true` from Google.
4. If a local user with the same email already exists, the service links the Google identity to that user.
5. Otherwise, the service creates a new verified user and links the external identity.

### Refresh Token Rotation

1. A client exchanges a refresh token at `POST /token`.
2. The service validates the refresh token, issues new access and ID tokens, and replaces the refresh token with a newly generated one.
3. The previously used refresh token is marked as consumed.
4. If a consumed refresh token is presented again, the service treats it as replay and invalidates the token family, forcing re-authentication.

### Logout

1. The user triggers logout through the hosted UI.
2. The service invalidates the hosted IdP session cookie or backing session record.
3. The next authorization attempt requires the user to log in again.

Logout does not revoke refresh tokens in the MVP.

## Token Design

### Access Token

- Format: JWT
- Signing algorithm: RS256
- Published key material: JWKS endpoint
- Intended audience: first-party resource servers
- Core claims:
  - `iss`
  - `sub`
  - `aud`
  - `exp`
  - `iat`
  - `nbf`
  - `jti`
  - `scope`

The service may additionally include `email` and `email_verified` in access tokens if doing so simplifies resource-server integration, but `GET /userinfo` remains the canonical OIDC user data endpoint.

### ID Token

- Format: JWT
- Signing algorithm: RS256
- Core claims:
  - `iss`
  - `sub`
  - `aud`
  - `exp`
  - `iat`
  - `auth_time`
  - `email`
  - `email_verified`
  - `nonce` when provided by the client

### Refresh Token

- Format: opaque random token
- Stored as: server-side state, preferably hashed before persistence
- Behavior: rotated on every successful use
- Security property: replay detection through token-family tracking

## Data Model

### `users`

- `id`
- `email`
- `password_hash` nullable for social-only accounts
- `email_verified`
- `status`
- `created_at`
- `updated_at`

### `external_identities`

- `id`
- `user_id`
- `provider`
- `provider_subject`
- `provider_email`
- `provider_email_verified`
- `created_at`

### `email_verification_tokens`

- `id`
- `user_id`
- `token_hash`
- `expires_at`
- `consumed_at`
- `created_at`

### `password_reset_tokens`

- `id`
- `user_id`
- `token_hash`
- `expires_at`
- `consumed_at`
- `created_at`

### `sessions`

- `id`
- `user_id`
- `expires_at`
- `revoked_at`
- `created_at`

### `authorization_codes`

- `id`
- `user_id`
- `client_id`
- `redirect_uri`
- `scope`
- `pkce_challenge`
- `pkce_challenge_method`
- `expires_at`
- `consumed_at`
- `created_at`

### `refresh_tokens`

- `id`
- `user_id`
- `token_hash`
- `family_id`
- `parent_token_id`
- `expires_at`
- `consumed_at`
- `revoked_at`
- `replay_detected`
- `created_at`

### `signing_keys`

- `id`
- `kid`
- `status`
- `public_jwk`
- `private_key_ref` or equivalent protected storage reference
- `created_at`
- `retired_at`

## Client Configuration

The MVP supports exactly one OAuth client. Its configuration lives in environment variables or config files and includes:

- `client_id`
- allowed redirect URIs
- supported scopes
- issuer base URL
- Google OAuth client credentials
- signing key material references
- session and cookie secrets

The implementation should avoid hard-coding assumptions that block future expansion to multiple clients, but it does not need a client registration API in the MVP.

## Security Requirements

- Require PKCE for all authorization code flows.
- Reject redirect URIs that do not exactly match configured allowlisted values.
- Store passwords only as strong password hashes.
- Validate Google tokens for issuer, audience, signature, expiry, and verified email status.
- Sign JWTs with RS256 and publish corresponding public keys at `GET /jwks`.
- Mark cookies `HttpOnly` and `Secure` outside local development.
- Choose an appropriate `SameSite` policy that does not break the hosted authorize flow.
- Apply rate limiting per IP and per identifier where applicable.
- Avoid leaking account existence in forgot-password and similar flows.
- Treat authorization codes, verification tokens, reset tokens, and refresh tokens as one-time or controlled-use credentials with explicit expiry.

## Error Handling

### User-Facing Behavior

- Use generic login errors such as "Invalid credentials."
- Do not reveal whether an email exists during forgot-password requests.
- Show clear expiration or invalid-token messages for verification and reset flows without exposing internals.

### OAuth2/OIDC Behavior

- Use standard OAuth2 error responses when appropriate:
  - `invalid_request`
  - `invalid_client`
  - `invalid_grant`
  - `unauthorized_client`
  - `unsupported_grant_type`
- Fail authorization code exchange cleanly on PKCE mismatch, code reuse, expiry, or redirect URI mismatch.
- Fail refresh exchange cleanly on replay, expiry, or revocation.

## Testing Strategy

### Unit Tests

- Password hashing and verification behavior.
- PKCE verification logic.
- Authorization code consumption rules.
- Token claim construction.
- Refresh token rotation and replay detection.
- Google account linking behavior.
- Email verification token lifecycle.
- Password reset token lifecycle.

### Integration Tests

- Signup -> verify email -> login -> authorize -> token exchange.
- Login through hosted UI into authorization code + PKCE flow.
- Forgot-password -> reset -> login.
- Google sign-in callback with mocked provider data.
- Discovery document and JWKS publication.
- JWT validation against published JWKS.

### Security-Oriented Tests

- Rejecting unknown or malformed redirect URIs.
- Rejecting unverified users from completing login/authorization.
- Rejecting reused authorization codes.
- Rejecting reused refresh tokens and invalidating the token family.
- Enforcing rate limits on repeated invalid login attempts.

## Observability

- Emit structured logs for:
  - login success and failure
  - signup
  - email verification requests and completion
  - password reset requests and completion
  - token issuance
  - refresh replay detection
  - Google login success and failure
- Avoid logging secrets, raw passwords, raw tokens, or personally sensitive data unnecessarily.

Metrics are optional in the MVP but recommended if easy to add.

## Open Technical Choices To Resolve During Planning

- Whether to use `bcrypt` or `argon2id` for password hashing.
- Whether session state is stored entirely in Postgres or split between signed cookies and database-backed sessions.
- Whether rate limiting is implemented in-process for MVP or backed by shared storage.
- Whether `GET /userinfo` alone carries user profile information or whether access tokens also include selected user claims.

These are implementation choices, not product-scope questions, and can be finalized in the implementation plan.

## Post-MVP Extensions

- TOTP-based MFA
- Refresh-token revocation on logout
- OIDC RP-initiated logout
- Multiple OAuth clients
- Additional social providers
- Production email delivery provider
- Automated signing key rotation
- Audit event storage and admin tooling
- Service-to-service OAuth flows
