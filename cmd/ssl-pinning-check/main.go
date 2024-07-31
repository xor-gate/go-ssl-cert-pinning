package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// hEx encoded SHA-256 hash of the certificate (*.google.com and www.google.com @ 31 july 2024 - 12:50)
const pinnedCertHashHexWildcard = "065e3b66390a5d3c7ce51f27342442606453b3d98e4d4e97f5b708b59d190a0a"
const pinnedCertHashHexWWW = "96999ef19ae0e2250cdc320c8875c1b6e9e47667bdea9900f92bcbebc3b304ea"

func verifyCommonName(commonName string) bool {
	for _, allowed := range allowedCNs {
		if strings.HasPrefix(allowed, "*.") {
			// Handle wildcard certificate
			if strings.HasSuffix(commonName, allowed[1:]) {
				return true
			}
		} else if commonName == allowed {
			// Handle exact match
			return true
		}
	}
	return false
}

// List of allowed Common Names (CN), including wildcards
var allowedCNs = []string{
	"www.google.com",
	"*.google.com",
}

func checkCert(cert *x509.Certificate) bool {
	hash := sha256.Sum256(cert.Raw)
	hashBase64 := base64.StdEncoding.EncodeToString(hash[:])
	hashHex := hex.EncodeToString(hash[:])

	log.Println("Remote cert", hashBase64)
	log.Println("Remote cert hex:", hashHex)

	// Extract the Common Name (CN) from the certificate's Subject
	commonName := cert.Subject.CommonName
	fmt.Println("Common Name (CN) of the certificate:", commonName)

	// Verify the Common Name (CN) against allowed patterns
	if !verifyCommonName(commonName) {
		log.Printf("certificate common name %s is not allowed\n", commonName)
		return false
	} else {
		log.Println("Common Name is trusted")
	}

	// Check if the computed hash matches the pinned hash
	if hashHex == pinnedCertHashHexWildcard || hashHex == pinnedCertHashHexWWW {
		log.Println("OK")
		return true // Certificate is pinned
	}
	return false
}

func main() {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Do not use this in production
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					checkCertOk := false

					log.Println("rawCerts count", len(rawCerts))
					// Probably verifiedChains is empty because using InsecureSkipVerify = true
					log.Println("verifiedChains count", len(verifiedChains)) 

					// Iterate over the rawCerts
					for _, rawCert := range rawCerts {
							// Parse the first certificate in the chain
							cert, err := x509.ParseCertificate(rawCert)
							if err != nil {
								return fmt.Errorf("failed to parse certificate: %v", err)
							}

							ok := checkCert(cert)
							if ok {
								checkCertOk = true
							}
					}

					// Iterate over the verified chains
					for _, chain := range verifiedChains {
						for _, cert := range chain {
							ok := checkCert(cert)
							if ok {
								checkCertOk = true
							}
						}
					}

					if checkCertOk {
						log.Println("checkCertOk")
						return nil
					}

					return fmt.Errorf("certificate pinning validation failed")
				},
			},
		},
	}

	resp, err := client.Get("https://google.com")
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Process the response
	log.Printf("Response status: %s", resp.Status)
}
