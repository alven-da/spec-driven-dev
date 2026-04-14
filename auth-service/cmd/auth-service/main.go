package main

import (
	"log"
	"net/http"

	httpadapter "auth-service/adapters/in/http"
	"auth-service/config"
)

func main() {
	cfg := config.Load()
	router := httpadapter.NewRouter()

	if err := http.ListenAndServe(cfg.Addr, router); err != nil {
		log.Fatal(err)
	}
}
