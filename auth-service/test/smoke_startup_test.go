package test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	httpadapter "auth-service/adapters/in/http"
	"auth-service/config"
)

func TestConfigLoadDefaultsAddr(t *testing.T) {
	t.Setenv("AUTH_SERVICE_ADDR", "")

	cfg := config.Load()

	if cfg.Addr != ":8080" {
		t.Fatalf("expected default addr %q, got %q", ":8080", cfg.Addr)
	}
}

func TestConfigLoadUsesEnvAddr(t *testing.T) {
	t.Setenv("AUTH_SERVICE_ADDR", ":9090")

	cfg := config.Load()

	if cfg.Addr != ":9090" {
		t.Fatalf("expected env addr %q, got %q", ":9090", cfg.Addr)
	}
}

func TestHealthzRouteReturnsOKForGET(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	router := httpadapter.NewRouter()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestHealthzRouteRejectsNonGET(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	rec := httptest.NewRecorder()

	router := httpadapter.NewRouter()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestServiceBootstraps(t *testing.T) {
	t.Run("loads default config", func(t *testing.T) {
		t.Setenv("AUTH_SERVICE_ADDR", "")

		cfg := config.Load()
		if cfg.Addr != ":8080" {
			t.Fatalf("expected default addr %q, got %q", ":8080", cfg.Addr)
		}
	})

	t.Run("loads env config", func(t *testing.T) {
		t.Setenv("AUTH_SERVICE_ADDR", ":9090")

		cfg := config.Load()
		if cfg.Addr != ":9090" {
			t.Fatalf("expected env addr %q, got %q", ":9090", cfg.Addr)
		}
	})

	t.Run("serves health endpoint with method guard", func(t *testing.T) {
		router := httpadapter.NewRouter()

		getReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		getRec := httptest.NewRecorder()
		router.ServeHTTP(getRec, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("expected GET status %d, got %d", http.StatusOK, getRec.Code)
		}

		postReq := httptest.NewRequest(http.MethodPost, "/healthz", nil)
		postRec := httptest.NewRecorder()
		router.ServeHTTP(postRec, postReq)
		if postRec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected POST status %d, got %d", http.StatusMethodNotAllowed, postRec.Code)
		}
	})
}
