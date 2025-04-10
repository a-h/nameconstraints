package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"sync"
)

func startServer(conf serverConf) (err error) {
	srv := &http.Server{
		Addr: conf.addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello from " + conf.addr))
		}),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	log.Printf("Starting HTTPS server at %s\n", conf.addr)
	return srv.ListenAndServeTLS(conf.certFile, conf.keyFile)
}

type serverConf struct {
	addr     string
	certFile string
	keyFile  string
}

func main() {
	/*
		   | Port | Domain         | Organisational Unit | Should Pass |
		   |------|----------------|---------------------|--------------|
		   | 8443 | Correct        | Correct             | Yes          |
		   | 8444 | Correct        | Incorrect           | No           |
		   | 8445 | Incorrect      | Correct             | No           |
		   | 8446 | Incorrect      | Incorrect           | No           |

			 filenames are: ca/certs/domain_correct_ou_correct.chain.pem, ca/certs/domain_correct_ou_correct.key.pem
	*/

	conf := []serverConf{
		{":8443", "ca/certs/domain_correct_ou_correct.chain.pem", "ca/certs/domain_correct_ou_correct.key.pem"},
		{":8444", "ca/certs/domain_incorrect_ou_correct.chain.pem", "ca/certs/domain_incorrect_ou_correct.key.pem"},
		{":8445", "ca/certs/domain_correct_ou_incorrect.chain.pem", "ca/certs/domain_correct_ou_incorrect.key.pem"},
		{":8446", "ca/certs/domain_incorrect_ou_incorrect.chain.pem", "ca/certs/domain_incorrect_ou_incorrect.key.pem"},
	}

	for _, conf := range conf {
		if _, err := tls.LoadX509KeyPair(conf.certFile, conf.keyFile); err != nil {
			log.Printf("Failed to load cert/key for %s: %v", conf.addr, err)
		}
	}

	errs := make(chan error)

	var wg sync.WaitGroup
	wg.Add(4)
	for _, c := range conf {
		go func(c serverConf) {
			defer wg.Done()
			if err := startServer(c); err != nil {
				errs <- fmt.Errorf("%s: %w", c.certFile, err)
			}
		}(c)
	}

	go func() {
		wg.Wait()
		close(errs)
	}()

	for err := range errs {
		if err != nil {
			log.Printf("%v\n", err)
		}
	}
}
