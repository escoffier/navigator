package util

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type JWT struct {
	SecretKey string
}

func NewJWT(secretKey string) *JWT {
	return &JWT{
		SecretKey: secretKey,
	}
}

const DownloadFileKey = "MDa8NSNQRcaZZnZO"

func (j *JWT) GenJWTToken(sub string, expire time.Duration) (string, error) {
	clm := jwt.StandardClaims{
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Unix() + int64(expire.Seconds()),
		Subject:   sub,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, clm)

	tokenString, err := token.SignedString([]byte(j.SecretKey))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (j *JWT) DecodeJwtToken(token string) (*jwt.StandardClaims, error) {
	clm := &jwt.StandardClaims{}
	jwtToken, err := jwt.ParseWithClaims(token, clm, j.keyFunc)
	if err != nil {
		return nil, err
	}

	clm2, ok := jwtToken.Claims.(*jwt.StandardClaims)
	if !ok {
		return nil, fmt.Errorf("not StandardClaims")
	}

	return clm2, nil
}

func (j *JWT) ValidateToken(token string) bool {
	jwtToken, err := j.DecodeJwtToken(token)
	if err != nil {
		return false
	}
	return jwtToken.Valid() == nil
}

func (j *JWT) keyFunc(token *jwt.Token) (i interface{}, err error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
		return []byte(j.SecretKey), nil
	} else {
		return nil, fmt.Errorf("expect token signed with HMAC but got %v", token.Header["alg"])
	}
}
