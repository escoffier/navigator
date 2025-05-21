package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	privateKey *rsa.PrivateKey
)

func init() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("Failed to generate private key")
	}
}

func GetPublicKeyN() string {
	pubKey := privateKey.PublicKey
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&pubKey)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	return base64.URLEncoding.EncodeToString(pubKeyPEM)
}

func GenerateJWT(userID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})
	return token.SignedString([]byte("your-secret-key"))
}

func init() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("Failed to generate private key")
	}
}

func GenerateRandomPwd(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("a", length)
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("a", length)
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

func GenerateIDToken(userID, clientID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"iss": "http://localhost:8080",
		"aud": clientID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "1"
	return token.SignedString(privateKey)
}
