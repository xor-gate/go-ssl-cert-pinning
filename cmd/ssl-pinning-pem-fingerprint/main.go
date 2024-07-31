package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	// Replace with the path to your PEM encoded SSL certificate file
	certPath := "path/to/your/certificate.pem"

	// Read the certificate file
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatalf("Failed to decode PEM block containing certificate")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}

	// Extract the Common Name (CN) from the certificate's Subject
	commonName := cert.Subject.CommonName

	// Print the Common Name (CN)
	fmt.Println("Common Name (CN) of the certificate:", commonName)
}
