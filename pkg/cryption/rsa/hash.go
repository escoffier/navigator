package rsa

import (
	"crypto/sha256"
	"fmt"
)

func Sha256(data []byte) ([]byte, error) {
	msgHash := sha256.New()
	_, err := msgHash.Write(data)
	if err != nil {
		panic(err)
	}
	return msgHash.Sum(nil), nil
}

func Sha256String(data []byte) (string, error) {
	h, err := Sha256(data)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h), nil
}
