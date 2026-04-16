package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"auth-service/core"
)

type OAuthHandlers struct {
	usecases *core.OAuthUsecases
	cookies  *SessionCookieCodec
}

func NewOAuthHandlers(usecases *core.OAuthUsecases, cookies *SessionCookieCodec) *OAuthHandlers {
	return &OAuthHandlers{usecases: usecases, cookies: cookies}
}

func (h *OAuthHandlers) Discovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	issuer := h.usecases.Issuer()
	response := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}

	writeJSON(w, http.StatusOK, response)
}

func (h *OAuthHandlers) JWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, h.usecases.JWKS())
}

func (h *OAuthHandlers) Authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	userID, err := h.sessionUserID(r)
	if err != nil {
		redirectToHostedLogin(w, r)
		return
	}

	query := r.URL.Query()
	if query.Get("response_type") != "code" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	code, err := h.usecases.CreateAuthorizationCode(r.Context(), core.CreateAuthorizationCodeInput{
		UserID:              userID,
		ClientID:            query.Get("client_id"),
		RedirectURI:         query.Get("redirect_uri"),
		Scope:               query.Get("scope"),
		Nonce:               query.Get("nonce"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
	})
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, core.ErrInvalidOAuthRequest) {
			status = http.StatusBadRequest
		}
		if errors.Is(err, core.ErrUnauthorized) {
			status = http.StatusBadRequest
		}
		w.WriteHeader(status)
		return
	}

	redirectURI, err := url.Parse(query.Get("redirect_uri"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	params := redirectURI.Query()
	params.Set("code", code)
	if state := query.Get("state"); state != "" {
		params.Set("state", state)
	}
	redirectURI.RawQuery = params.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

func (h *OAuthHandlers) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}

	tokenSet, err := h.usecases.ExchangeCode(r.Context(), core.ExchangeAuthorizationCodeInput{
		Code:         r.Form.Get("code"),
		ClientID:     r.Form.Get("client_id"),
		RedirectURI:  r.Form.Get("redirect_uri"),
		CodeVerifier: r.Form.Get("code_verifier"),
	})
	if err != nil {
		status := http.StatusInternalServerError
		payload := map[string]string{"error": "server_error"}
		if errors.Is(err, core.ErrInvalidOAuthRequest) {
			status = http.StatusBadRequest
			payload = map[string]string{"error": "invalid_request"}
		}
		if errors.Is(err, core.ErrUnauthorized) {
			status = http.StatusBadRequest
			payload = map[string]string{"error": "invalid_client"}
		}
		if errors.Is(err, core.ErrInvalidGrant) {
			status = http.StatusBadRequest
			payload = map[string]string{"error": "invalid_grant"}
		}
		writeJSON(w, status, payload)
		return
	}

	writeJSON(w, http.StatusOK, tokenSet)
}

func (h *OAuthHandlers) UserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	payload, err := h.usecases.UserInfo(r.Context(), strings.TrimPrefix(authHeader, "Bearer "))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

func (h *OAuthHandlers) sessionUserID(r *http.Request) (int64, error) {
	cookie, err := r.Cookie("auth_session")
	if err != nil {
		return 0, err
	}

	return h.cookies.DecodeUserID(cookie.Value)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func redirectToHostedLogin(w http.ResponseWriter, r *http.Request) {
	params := url.Values{}
	for _, key := range []string{
		"client_id",
		"redirect_uri",
		"scope",
		"state",
		"nonce",
		"code_challenge",
		"code_challenge_method",
	} {
		value := r.URL.Query().Get(key)
		if value != "" {
			params.Set(key, value)
		}
	}

	target := "/login"
	if encoded := params.Encode(); encoded != "" {
		target += "?" + encoded
	}
	http.Redirect(w, r, target, http.StatusFound)
}
