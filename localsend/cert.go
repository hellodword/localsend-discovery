package localsend

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"time"
)

func GenerateCert(certPath, keyPath string) (fingerprint string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	keyUsage := x509.KeyUsageDigitalSignature
	keyUsage |= x509.KeyUsageKeyEncipherment

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour * 10)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         "LocalSend User", // CN
			Organization:       []string{""},     // O
			OrganizationalUnit: []string{""},     // OU
			Country:            []string{""},     // C
			Locality:           []string{""},     // L
			Province:           []string{""},     // ST
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return
	}

	// https://gchq.github.io/CyberChef/#recipe=Find_/_Replace(%7B'option':'Regex','string':'%5E%5C%5C-%5B%5E%5C%5Cn%5D%2B$'%7D,'',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':'%5C%5Cn'%7D,'',true,false,true,false)From_Base64('A-Za-z0-9%2B/%3D',true,false)SHA2('256',64,160)
	// openssl s_client -connect 127.0.0.1:53317
	hash := sha256.Sum256(der)
	fingerprint = strings.ToUpper(hex.EncodeToString(hash[:]))

	certOut, err := os.Create(certPath)
	if err != nil {
		return
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err != nil {
		return
	}
	err = certOut.Close()
	if err != nil {
		return
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if err != nil {
		return
	}
	err = keyOut.Close()
	if err != nil {
		return
	}

	return
}
