package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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

func ShortUUID() string {
	id := uuid.New().String()
	return id[:8] // 截取标准UUID前8位
}

var secretKey = []byte("thisis32bitlongpassphraseimusing") // 32字节密钥

func EncryptTimestamp(timestamp int64) string {
	// 将时间戳转换为字符串
	text := strconv.FormatInt(timestamp, 10)

	// 创建加密块
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return ""
	}

	// 创建GCM模式的加密器
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}

	// 创建nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return ""
	}

	// 加密数据
	ciphertext := gcm.Seal(nonce, nonce, []byte(text), nil)

	// 返回Base64编码的字符串
	return base64.URLEncoding.EncodeToString(ciphertext)
}

func DecryptToTimestamp(encrypted string) int64 {
	// 解码Base64字符串
	data, err := base64.URLEncoding.DecodeString(encrypted)
	if err != nil {
		return 0
	}

	// 创建加密块
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return 0
	}

	// 创建GCM模式的解密器
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	// 检查数据长度
	if len(data) < gcm.NonceSize() {
		return 0
	}

	// 分离nonce和实际密文
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]

	// 解密数据
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0
	}

	// 将字符串转换为时间戳
	timestamp, err := strconv.ParseInt(string(plaintext), 10, 64)
	if err != nil {
		return 0
	}
	return timestamp
}
