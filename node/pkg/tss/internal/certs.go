package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"time"
)

// CertTemplate is a helper function to create a cert template with a serial number and other required fields
func CertTemplate() (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number: " + err.Error())
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"tsscomm"}},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 366 * 40), // valid for > 40 years
		BasicConstraintsValid: true,
	}
	return &tmpl, nil
}

// CreateCert invokes x509.CreateCertificate and returns it in the x509.Certificate format
func CreateCert(template, parent *x509.Certificate, pub *ecdsa.PublicKey, parentPriv *ecdsa.PrivateKey) (
	cert *x509.Certificate, certPEM []byte, err error) {

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return
}

// NewTLSCredentials creates a self signed certificate
func NewTLSCredentials() (*x509.Certificate, *ecdsa.PrivateKey) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("couldn't create private key: %v", err)
	}
	rootCertTmpl, err := CertTemplate()
	if err != nil {
		log.Fatalf("creating cert template: %v", err)
	}

	// this cert will be the CA that we will use to sign the server cert
	rootCertTmpl.IsCA = true
	// describe what the certificate will be used for
	rootCertTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	rootCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

	rootCert, _, err := CreateCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		log.Fatalf("error creating cert: %v", err)
	}

	// keyBytes, err := x509.MarshalPKCS8PrivateKey(rootKey)
	// if err != nil {
	// 	log.Fatal("shouldn't happen")
	// }

	// servKeyPEM := pem.EncodeToMemory(&pem.Block{
	// 	Type: "RSA PRIVATE KEY", Bytes: keyBytes,
	// })

	// rootTlsCert, err := tls.X509KeyPair(rootPem, servKeyPEM)
	// if err != nil {
	// 	log.Fatalf("invalid key pair: %v", err)
	// }

	return rootCert, rootKey
}

func KeyToPem(pkey *ecdsa.PrivateKey) []byte {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(pkey)
	if err != nil {
		log.Fatal("shouldn't happen")
	}

	return pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: keyBytes,
	})
}

func CertToPem(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func PemToCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing the certificate")
	}
	if block.Type != "CERTIFICATE" {
		return nil, errors.New("PEM block is not a certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}
