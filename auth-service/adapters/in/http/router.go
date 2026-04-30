package http

import "net/http"

func NewRouter(handlers ...any) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	for _, handler := range handlers {
		authHandlers, ok := handler.(*AuthHandlers)
		if ok && authHandlers != nil {
			mux.HandleFunc("/signup", authHandlers.Signup)
			mux.HandleFunc("/verify-email", authHandlers.VerifyEmail)
			mux.HandleFunc("/login", authHandlers.Login)
		}

		oauthHandlers, ok := handler.(*OAuthHandlers)
		if ok && oauthHandlers != nil {
			mux.HandleFunc("/.well-known/openid-configuration", oauthHandlers.Discovery)
			mux.HandleFunc("/jwks", oauthHandlers.JWKS)
			mux.HandleFunc("/authorize", oauthHandlers.Authorize)
			mux.HandleFunc("/token", oauthHandlers.Token)
			mux.HandleFunc("/userinfo", oauthHandlers.UserInfo)
		}
	}

	return mux
}
