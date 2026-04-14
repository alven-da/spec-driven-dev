package http

import "net/http"

func NewRouter(authHandlers ...*AuthHandlers) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	if len(authHandlers) > 0 && authHandlers[0] != nil {
		mux.HandleFunc("/signup", authHandlers[0].Signup)
		mux.HandleFunc("/verify-email", authHandlers[0].VerifyEmail)
		mux.HandleFunc("/login", authHandlers[0].Login)
	}

	return mux
}
