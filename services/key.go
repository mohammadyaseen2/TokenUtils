package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"token-utils/models"
)

func MakeKeyPair(bits int) (*models.KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Cannot generate RSA key: %s", err))
	}
	publicKey := &privateKey.PublicKey

	// dump private key to file
	var privateKeyBytes = x509.MarshalPKCS1PrivateKey(privateKey)

	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("error when dumping publickey: %s", err))
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	return &models.KeyPair{
		PrivateKey: pem.EncodeToMemory(privateKeyBlock),
		PublicKey:  pem.EncodeToMemory(publicKeyBlock),
	}, nil
}
