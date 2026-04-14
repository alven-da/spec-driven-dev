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

	verifier := "mvp-pkce-verifier-1234567890"
	challenge := pkceChallengeS256(t, verifier)

	authorizeReq := httptest.NewRequest(
		http.MethodGet,
		"/authorize?response_type=code&client_id=web-client&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=openid+profile&state=abc123&code_challenge_method=S256&code_challenge="+url.QueryEscape(challenge),
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
	form.Set("redirect_uri", "https://app.example.com/callback")
	form.Set("client_id", "web-client")
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
}

func pkceChallengeS256(t *testing.T, verifier string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
