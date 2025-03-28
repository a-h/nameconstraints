package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func makeRequest(addr, serverName string, expectedOK bool) {
	rootCA := x509.NewCertPool()
	caCert, err := os.ReadFile("ca/root/root.cert.pem")
	if err != nil {
		log.Fatalf("reading root CA: %v", err)
	}
	if ok := rootCA.AppendCertsFromPEM(caCert); !ok {
		log.Fatal("failed to append root CA")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    rootCA,
			ServerName: serverName, // TLS override
		},
	}

	client := &http.Client{Transport: tr}

	url := "https://localhost" + addr
	resp, err := client.Get(url)
	if err != nil {
		if expectedOK {
			fmt.Printf("\033[31m✘\033[0m ")
			fmt.Printf("Request to %s (as %s) failed: %v\n", addr, serverName, err)
		} else {
			fmt.Printf("\033[32m✔\033[0m ")
			fmt.Printf("Request to %s (as %s) failed as expected: %v\n", addr, serverName, err)
		}
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
	if expectedOK {
		fmt.Printf("\033[32m✔\033[0m ")
		fmt.Printf("Request to %s (as %s) succeeded\n", addr, serverName)
	} else {
		fmt.Printf("\033[31m✘\033[0m ")
		fmt.Printf("Request to %s (as %s) succeeded but was not expected to\n", addr, serverName)
	}
}

func main() {
	fmt.Println("Correct domain and organization")
	makeRequest(":8443", "only-this-domain-is-allowed.com", true)
	fmt.Println()
	fmt.Println("Correct domain but wrong organization")
	makeRequest(":8444", "only-this-domain-is-allowed.com", false)
	fmt.Println()
	fmt.Println("Incorrect domain but correct organization")
	makeRequest(":8445", "this-domain-is-not-allowed.com", false)
}
