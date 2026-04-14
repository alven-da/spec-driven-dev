package main

import (
	"context"
	"log"
	"net/http"

	httpadapter "auth-service/adapters/in/http"
	jwtadapter "auth-service/adapters/out/jwt"
	maileradapter "auth-service/adapters/out/mailer"
	postgresadapter "auth-service/adapters/out/postgres"
	"auth-service/config"
	"auth-service/core"
)

func main() {
	cfg := config.Load()

	db, err := postgresadapter.OpenDB(context.Background(), cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = db.Close()
	}()

	usersRepo := postgresadapter.NewUsersRepo(db)
	oauthRepo := postgresadapter.NewOAuthRepo(db)
	mailer := maileradapter.NewLoggerMailer(log.Default())
	authUsecases := core.NewAuthUsecases(usersRepo, mailer)
	authHandlers := httpadapter.NewAuthHandlers(authUsecases, cfg.CookieSecure)

	signer, err := jwtadapter.NewSigner("http://localhost" + cfg.Addr)
	if err != nil {
		log.Fatal(err)
	}
	oauthUsecases := core.NewOAuthUsecases(oauthRepo, signer)
	oauthHandlers := httpadapter.NewOAuthHandlers(oauthUsecases)

	router := httpadapter.NewRouter(authHandlers, oauthHandlers)

	if err := http.ListenAndServe(cfg.Addr, router); err != nil {
		log.Fatal(err)
	}
}
