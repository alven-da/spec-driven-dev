package main

import (
	"context"
	"log"
	"net/http"

	httpadapter "auth-service/adapters/in/http"
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
	mailer := maileradapter.NewLoggerMailer(log.Default())
	usecases := core.NewAuthUsecases(usersRepo, mailer)
	handlers := httpadapter.NewAuthHandlers(usecases, cfg.CookieSecure)
	router := httpadapter.NewRouter(handlers)

	if err := http.ListenAndServe(cfg.Addr, router); err != nil {
		log.Fatal(err)
	}
}
