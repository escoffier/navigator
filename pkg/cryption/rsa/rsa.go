package rsa

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

type KeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

// GenerateRSA 生成一个rsa对
func GenerateRSA(ctx context.Context) (*KeyPair, error) {

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate an RSA keypair")
	}
	var privateKeyBytes = x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privateBuffer := bytes.NewBuffer(nil)
	err = pem.Encode(privateBuffer, privateKeyBlock)
	if err != nil {
		return nil, errors.Wrap(err, "failed to write private key to buffer")
	}

	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal public key")
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	publicBuffer := bytes.NewBuffer(nil)
	err = pem.Encode(publicBuffer, publicKeyBlock)
	if err != nil {
		return nil, errors.Wrap(err, "failed to write public key to buffer")
	}

	rsaResult := &KeyPair{
		PrivateKey: privateBuffer.Bytes(),
		PublicKey:  publicBuffer.Bytes(),
	}

	return rsaResult, nil
}
