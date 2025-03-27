package main

import (
	"crypto/tls"
	"log"
	"net/http"
)

func startServer(addr, certFile, keyFile string) {
	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello from " + addr))
		}),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	log.Printf("Starting HTTPS server at %s\n", addr)
	log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
}

func main() {
	go startServer(":8443", "ca/certs/allowed.chain.pem", "ca/certs/allowed.key.pem")
	go startServer(":8444", "ca/certs/not_allowed.chain.pem", "ca/certs/not_allowed.key.pem")

	select {} // block forever
}
