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

// createCustomVerifierClient creates an HTTP client with a custom TLS configuration
// that verifies TLS certs using a custom verifier that supports critical dirName
// name constraints.
func createCustomVerifierClient(rootCA *x509.CertPool, serverName string) *http.Client {
	cv := NewCertVerifier(rootCA)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:               rootCA,
			ServerName:            serverName, // TLS override, because we're using localhost.
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: cv.VerifyPeerCertificate(serverName),
		},
	}
	return &http.Client{Transport: tr}
}

func createStandardClient(rootCA *x509.CertPool, serverName string) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:            rootCA,
			ServerName:         serverName, // TLS override, because we're using localhost.
			InsecureSkipVerify: false,
		},
	}
	return &http.Client{Transport: tr}
}

func testRequest(conf clientConf, client *http.Client) {
	url := "https://localhost" + conf.addr
	resp, err := client.Get(url)
	if err != nil {
		if conf.expectedOK {
			fmt.Printf("  \033[31m✘\033[0m ")
			fmt.Printf("Request to %s (as %s) failed: %v\n", conf.addr, conf.serverName, err)
		} else {
			fmt.Printf("  \033[32m✔\033[0m ")
			fmt.Printf("Request to %s (as %s) failed as expected: %v\n", conf.addr, conf.serverName, err)
		}
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if conf.expectedOK {
		fmt.Printf("  \033[32m✔\033[0m ")
		fmt.Printf("Request to %s (as %s) succeeded\n", conf.addr, conf.serverName)
		fmt.Println("    - Response:", string(body))
	} else {
		fmt.Printf("  \033[31m✘\033[0m ")
		fmt.Printf("Request to %s (as %s) succeeded but was not expected to\n", conf.addr, conf.serverName)
	}
}

type clientConf struct {
	name       string
	addr       string
	serverName string
	expectedOK bool
}

func main() {
	rootCA := x509.NewCertPool()
	caCert, err := os.ReadFile("ca/root/root.cert.pem")
	if err != nil {
		log.Fatalf("reading root CA: %v", err)
	}
	if ok := rootCA.AppendCertsFromPEM(caCert); !ok {
		log.Fatal("failed to append root CA")
	}

	conf := []clientConf{
		{name: "domain_correct_ou_correct", addr: ":8443", serverName: "only-this-domain-is-allowed.com", expectedOK: true},
		{name: "domain_incorrect_ou_correct", addr: ":8444", serverName: "only-this-domain-is-allowed.com", expectedOK: false},
		{name: "domain_correct_ou_incorrect", addr: ":8445", serverName: "this-domain-is-not-allowed.com", expectedOK: false},
		{name: "domain_incorrect_ou_incorrect", addr: ":8446", serverName: "this-domain-is-not-allowed.com", expectedOK: false},
	}

	fmt.Println()
	fmt.Println("Testing using the standard TLS client")
	fmt.Println("=====================================")
	fmt.Println()
	for _, c := range conf {
		fmt.Printf("Testing %s\n", c.name)
		testRequest(c, createStandardClient(rootCA, c.serverName))
		fmt.Println()
	}

	fmt.Println()
	fmt.Println("Testing using the custom TLS client")
	fmt.Println("===================================")
	fmt.Println()
	for _, c := range conf {
		fmt.Printf("Testing %s\n", c.name)
		testRequest(c, createCustomVerifierClient(rootCA, c.serverName))
		fmt.Println()
	}
}
