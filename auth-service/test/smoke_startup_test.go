package test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	httpadapter "auth-service/adapters/in/http"
)

func TestHealthzRouteReturnsOK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	router := httpadapter.NewRouter()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}
