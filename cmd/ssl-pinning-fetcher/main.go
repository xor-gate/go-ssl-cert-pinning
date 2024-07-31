package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
)

func main() {
	url := "https://google.com"

	// Create a custom HTTP transport
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	// Create a new HTTP client
	client := &http.Client{Transport: tr}

	// Make a GET request
	resp, err := client.Get(url)
	if err != nil {
		log.Fatalf("Failed to get URL: %v", err)
	}
	defer resp.Body.Close()

	// Get the TLS connection state
	tlsState := resp.TLS
	if tlsState == nil {
		log.Fatalf("No TLS connection state found")
	}

	// Get the remote server's certificate
	log.Println("PeerCertificates count:", len(tlsState.PeerCertificates))

	for _, cert := range tlsState.PeerCertificates {
		// Compute the SHA-256 hash of the certificate
		hash := sha256.Sum256(cert.Raw)

		// Encode the hash in base64
		hashBase64 := base64.StdEncoding.EncodeToString(hash[:])
		hashHex := hex.EncodeToString(hash[:])

		// Print the base64 encoded hash
		fmt.Println("Base64 encoded SHA-256 hash of the certificate:", hashBase64)
		fmt.Println("Hex encoded SHA-256 hash of the certificate:", hashHex)
	}
}
