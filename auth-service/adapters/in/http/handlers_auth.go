package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"auth-service/core"
)

type AuthHandlers struct {
	usecases *core.AuthUsecases
}

func NewAuthHandlers(usecases *core.AuthUsecases) *AuthHandlers {
	return &AuthHandlers{usecases: usecases}
}

func (h *AuthHandlers) Signup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := h.usecases.Signup(r.Context(), req.Email, req.Password); err != nil {
		switch {
		case errors.Is(err, core.ErrInvalidInput):
			w.WriteHeader(http.StatusBadRequest)
		case errors.Is(err, core.ErrUserAlreadyExists):
			w.WriteHeader(http.StatusConflict)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *AuthHandlers) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := h.usecases.VerifyEmail(r.Context(), req.Token); err != nil {
		switch {
		case errors.Is(err, core.ErrInvalidInput), errors.Is(err, core.ErrInvalidVerificationToken):
			w.WriteHeader(http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *AuthHandlers) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	session, err := h.usecases.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrInvalidInput):
			w.WriteHeader(http.StatusBadRequest)
		case errors.Is(err, core.ErrEmailNotVerified):
			w.WriteHeader(http.StatusForbidden)
		case errors.Is(err, core.ErrInvalidCredentials):
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_session",
		Value:    strconv.FormatInt(session.UserID, 10),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusOK)
}
