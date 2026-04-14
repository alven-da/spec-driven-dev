package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Addr         string
	DatabaseURL  string
	CookieSecure bool
}

func Load() Config {
	addr := os.Getenv("AUTH_SERVICE_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	databaseURL := os.Getenv("AUTH_SERVICE_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://postgres:postgres@localhost:5432/auth_service?sslmode=disable"
	}

	cookieSecure := defaultCookieSecure(os.Getenv("AUTH_SERVICE_ENV"))
	if rawCookieSecure := os.Getenv("AUTH_SERVICE_COOKIE_SECURE"); rawCookieSecure != "" {
		parsed, err := strconv.ParseBool(rawCookieSecure)
		if err == nil {
			cookieSecure = parsed
		}
	}

	return Config{
		Addr:         addr,
		DatabaseURL:  databaseURL,
		CookieSecure: cookieSecure,
	}
}

func defaultCookieSecure(env string) bool {
	normalized := strings.ToLower(strings.TrimSpace(env))
	switch normalized {
	case "local", "dev", "development", "test":
		return false
	default:
		return true
	}
}
