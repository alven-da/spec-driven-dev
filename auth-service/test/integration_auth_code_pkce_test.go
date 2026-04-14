package test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	testOAuthClientID    = "web-client"
	testOAuthRedirectURI = "https://app.example.com/callback"
)

func TestAuthCodePKCEFlow(t *testing.T) {
	router, mailerOutput := newTestAuthRouter(false, false)

	signupPayload := map[string]string{
		"email":    "pkce-user@example.com",
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
		t.Fatal("expected auth_session cookie")
	}

	verifier := "mvp-pkce-verifier-1234567890-abcdefghijklmnopqrstuvwxyz"
	challenge := pkceChallengeS256(t, verifier)

	authorizeReq := httptest.NewRequest(
		http.MethodGet,
		"/authorize?response_type=code&client_id=web-client&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=openid+profile&state=abc123&nonce=nonce-123&code_challenge_method=S256&code_challenge="+url.QueryEscape(challenge),
		nil,
	)
	authorizeReq.AddCookie(cookies[0])
	authorizeResp := httptest.NewRecorder()
	router.ServeHTTP(authorizeResp, authorizeReq)

	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status %d, got %d", http.StatusFound, authorizeResp.Code)
	}
	location := authorizeResp.Result().Header.Get("Location")
	if location == "" {
		t.Fatal("expected redirect location from authorize")
	}
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse authorize redirect location: %v", err)
	}
	authCode := redirectURL.Query().Get("code")
	if authCode == "" {
		t.Fatalf("expected auth code in redirect query, got location %q", location)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", authCode)
	form.Set("redirect_uri", testOAuthRedirectURI)
	form.Set("client_id", testOAuthClientID)
	form.Set("code_verifier", verifier)
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResp := httptest.NewRecorder()
	router.ServeHTTP(tokenResp, tokenReq)

	if tokenResp.Code != http.StatusOK {
		t.Fatalf("expected token status %d, got %d", http.StatusOK, tokenResp.Code)
	}

	var tokenSet struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(tokenResp.Body.Bytes(), &tokenSet); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokenSet.AccessToken == "" || tokenSet.IDToken == "" || tokenSet.RefreshToken == "" {
		t.Fatalf("expected access_token, id_token and refresh_token, got %#v", tokenSet)
	}
	if tokenSet.TokenType != "Bearer" {
		t.Fatalf("expected token_type Bearer, got %q", tokenSet.TokenType)
	}
	claims := decodeJWTClaims(t, tokenSet.IDToken)
	if claims["nonce"] != "nonce-123" {
		t.Fatalf("expected nonce claim %q, got %#v", "nonce-123", claims["nonce"])
	}
	if claims["email"] != "pkce-user@example.com" {
		t.Fatalf("expected email claim, got %#v", claims["email"])
	}
	if claims["email_verified"] != true {
		t.Fatalf("expected email_verified=true, got %#v", claims["email_verified"])
	}
	if _, ok := claims["auth_time"]; !ok {
		t.Fatal("expected auth_time claim in id_token")
	}

	discoveryResp := httptest.NewRecorder()
	router.ServeHTTP(discoveryResp, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if discoveryResp.Code != http.StatusOK {
		t.Fatalf("expected discovery status %d, got %d", http.StatusOK, discoveryResp.Code)
	}

	jwksResp := httptest.NewRecorder()
	router.ServeHTTP(jwksResp, httptest.NewRequest(http.MethodGet, "/jwks", nil))
	if jwksResp.Code != http.StatusOK {
		t.Fatalf("expected jwks status %d, got %d", http.StatusOK, jwksResp.Code)
	}

	userinfoReq := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	userinfoReq.Header.Set("Authorization", "Bearer "+tokenSet.AccessToken)
	userinfoResp := httptest.NewRecorder()
	router.ServeHTTP(userinfoResp, userinfoReq)
	if userinfoResp.Code != http.StatusOK {
		t.Fatalf("expected userinfo status %d, got %d", http.StatusOK, userinfoResp.Code)
	}

	idTokenUserInfoReq := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	idTokenUserInfoReq.Header.Set("Authorization", "Bearer "+tokenSet.IDToken)
	idTokenUserInfoResp := httptest.NewRecorder()
	router.ServeHTTP(idTokenUserInfoResp, idTokenUserInfoReq)
	if idTokenUserInfoResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected userinfo with id_token status %d, got %d", http.StatusUnauthorized, idTokenUserInfoResp.Code)
	}
}

func TestAuthorizeRejectsInvalidClientAndRedirect(t *testing.T) {
	router, _, cookie := setupVerifiedSession(t)
	verifier := "mvp-pkce-verifier-1234567890-abcdefghijklmnopqrstuvwxyz"
	challenge := pkceChallengeS256(t, verifier)

	invalidClientReq := httptest.NewRequest(
		http.MethodGet,
		"/authorize?response_type=code&client_id=other-client&redirect_uri="+url.QueryEscape(testOAuthRedirectURI)+"&scope=openid&code_challenge_method=S256&code_challenge="+url.QueryEscape(challenge),
		nil,
	)
	invalidClientReq.AddCookie(cookie)
	invalidClientResp := httptest.NewRecorder()
	router.ServeHTTP(invalidClientResp, invalidClientReq)
	if invalidClientResp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid client authorize status %d, got %d", http.StatusBadRequest, invalidClientResp.Code)
	}

	invalidRedirectReq := httptest.NewRequest(
		http.MethodGet,
		"/authorize?response_type=code&client_id="+testOAuthClientID+"&redirect_uri="+url.QueryEscape("https://evil.example.com/callback")+"&scope=openid&code_challenge_method=S256&code_challenge="+url.QueryEscape(challenge),
		nil,
	)
	invalidRedirectReq.AddCookie(cookie)
	invalidRedirectResp := httptest.NewRecorder()
	router.ServeHTTP(invalidRedirectResp, invalidRedirectReq)
	if invalidRedirectResp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid redirect authorize status %d, got %d", http.StatusBadRequest, invalidRedirectResp.Code)
	}
}

func TestAuthorizeRejectsTamperedSessionCookie(t *testing.T) {
	router, _, cookie := setupVerifiedSession(t)
	verifier := "mvp-pkce-verifier-1234567890-abcdefghijklmnopqrstuvwxyz"
	challenge := pkceChallengeS256(t, verifier)

	tampered := *cookie
	tampered.Value = "9999"

	req := httptest.NewRequest(
		http.MethodGet,
		"/authorize?response_type=code&client_id="+testOAuthClientID+"&redirect_uri="+url.QueryEscape(testOAuthRedirectURI)+"&scope=openid&code_challenge_method=S256&code_challenge="+url.QueryEscape(challenge),
		nil,
	)
	req.AddCookie(&tampered)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected tampered cookie authorize status %d, got %d", http.StatusUnauthorized, resp.Code)
	}
}

func TestTokenRejectsUnsupportedGrantTypeAndInvalidClientOrRedirect(t *testing.T) {
	router, authCode, _ := authorizeCodeForVerifiedUser(t, "")
	verifier := "mvp-pkce-verifier-1234567890-abcdefghijklmnopqrstuvwxyz"

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("code", authCode)
	form.Set("redirect_uri", testOAuthRedirectURI)
	form.Set("client_id", testOAuthClientID)
	form.Set("code_verifier", verifier)
	unsupportedResp := httptest.NewRecorder()
	unsupportedReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	unsupportedReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(unsupportedResp, unsupportedReq)
	assertOAuthError(t, unsupportedResp, http.StatusBadRequest, "unsupported_grant_type")

	form = url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", authCode)
	form.Set("redirect_uri", testOAuthRedirectURI)
	form.Set("client_id", "other-client")
	form.Set("code_verifier", verifier)
	invalidClientResp := httptest.NewRecorder()
	invalidClientReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	invalidClientReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(invalidClientResp, invalidClientReq)
	assertOAuthError(t, invalidClientResp, http.StatusBadRequest, "invalid_client")

	router, authCode, _ = authorizeCodeForVerifiedUser(t, "")
	form = url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", authCode)
	form.Set("redirect_uri", "https://evil.example.com/callback")
	form.Set("client_id", testOAuthClientID)
	form.Set("code_verifier", verifier)
	invalidRedirectResp := httptest.NewRecorder()
	invalidRedirectReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	invalidRedirectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(invalidRedirectResp, invalidRedirectReq)
	assertOAuthError(t, invalidRedirectResp, http.StatusBadRequest, "invalid_request")
}

func pkceChallengeS256(t *testing.T, verifier string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func setupVerifiedSession(t *testing.T) (http.Handler, string, *http.Cookie) {
	t.Helper()
	router, mailerOutput := newTestAuthRouter(false, false)
	signupPayload := map[string]string{"email": "pkce-user@example.com", "password": "very-secret"}
	if resp := doJSONRequest(t, router, http.MethodPost, "/signup", signupPayload); resp.Code != http.StatusOK {
		t.Fatalf("expected signup status %d, got %d", http.StatusOK, resp.Code)
	}
	token := extractVerificationToken(t, mailerOutput.String())
	if resp := doJSONRequest(t, router, http.MethodPost, "/verify-email", map[string]string{"token": token}); resp.Code != http.StatusOK {
		t.Fatalf("expected verify status %d, got %d", http.StatusOK, resp.Code)
	}
	loginResp := doJSONRequest(t, router, http.MethodPost, "/login", signupPayload)
	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected login status %d, got %d", http.StatusOK, loginResp.Code)
	}
	cookies := loginResp.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected auth_session cookie")
	}
	return router, signupPayload["email"], cookies[0]
}

func authorizeCodeForVerifiedUser(t *testing.T, nonce string) (http.Handler, string, string) {
	t.Helper()
	router, _, cookie := setupVerifiedSession(t)
	verifier := "mvp-pkce-verifier-1234567890-abcdefghijklmnopqrstuvwxyz"
	challenge := pkceChallengeS256(t, verifier)
	path := "/authorize?response_type=code&client_id=" + testOAuthClientID +
		"&redirect_uri=" + url.QueryEscape(testOAuthRedirectURI) +
		"&scope=openid+profile&state=abc123&code_challenge_method=S256&code_challenge=" + url.QueryEscape(challenge)
	if nonce != "" {
		path += "&nonce=" + url.QueryEscape(nonce)
	}
	authorizeReq := httptest.NewRequest(http.MethodGet, path, nil)
	authorizeReq.AddCookie(cookie)
	authorizeResp := httptest.NewRecorder()
	router.ServeHTTP(authorizeResp, authorizeReq)
	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status %d, got %d", http.StatusFound, authorizeResp.Code)
	}
	redirectURL, err := url.Parse(authorizeResp.Result().Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	authCode := redirectURL.Query().Get("code")
	if authCode == "" {
		t.Fatal("expected auth code in redirect location")
	}
	return router, authCode, verifier
}

func assertOAuthError(t *testing.T, resp *httptest.ResponseRecorder, expectedStatus int, expectedError string) {
	t.Helper()
	if resp.Code != expectedStatus {
		t.Fatalf("expected status %d, got %d body=%s", expectedStatus, resp.Code, resp.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode oauth error payload: %v", err)
	}
	if payload["error"] != expectedError {
		t.Fatalf("expected oauth error %q, got %#v", expectedError, payload["error"])
	}
}

func decodeJWTClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid jwt token format: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode jwt claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal jwt claims: %v", err)
	}
	return claims
}
