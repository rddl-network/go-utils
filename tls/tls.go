package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// Get2WayTLSClient creates a Go HTTP client for TLS web client authentication.
func Get2WayTLSClient(caCertPath, clientCertPath, clientKeyPath string) (client *http.Client, err error) {
	// Load CA cert
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		fmt.Printf("Error loading CA certificate: %v\n", err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Load client key pair
	cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		fmt.Printf("Error loading client certificate: %v\n", err)
		return
	}

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	return
}
