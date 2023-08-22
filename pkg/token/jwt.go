package token

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	DefaultIssuerName = "Tensor"
)

type Claims struct {
	Payload
	// Currently, we are not using any field in jwt.StandardClaims
	jwt.RegisteredClaims
}

type jwtToken struct {
	name       string
	signKey    interface{}
	verifyKey  interface{}
	signMethod jwt.SigningMethod
}

func (jt *jwtToken) Verify(tokenString string) (*Payload, error) {
	clm := Claims{}
	// verify token signature and expiration time
	_, err := jwt.ParseWithClaims(tokenString, &clm, jt.keyFunc)
	if err != nil {
		logging.Get().Info().Err(err).Msg("")
		return &clm.Payload, err
	}

	return &clm.Payload, nil
}

func (jt *jwtToken) IssueTo(payload Payload, expiresIn time.Duration) (string, error) {
	issueAt := jwt.NewNumericDate(time.Now())
	notBefore := issueAt
	clm := &Claims{
		Payload: payload,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  issueAt,
			Issuer:    jt.name,
			NotBefore: notBefore,
		},
	}

	if expiresIn > 0 {
		clm.ExpiresAt = jwt.NewNumericDate(clm.IssuedAt.Add(expiresIn))
	}

	token := jwt.NewWithClaims(jt.signMethod, clm)

	tokenString, err := token.SignedString(jt.signKey)
	if err != nil {
		logging.Get().Info().Err(err).Msg("")
		return "", err
	}

	return tokenString, nil
}

func (jt *jwtToken) keyFunc(t *jwt.Token) (interface{}, error) {
	if jt.verifyKey != nil {
		return jt.verifyKey, nil
	} else {
		return jt.signKey, nil
	}
}

type Option func(o *jwtToken)

func SetVerifyKey(verifyKey []byte) Option {
	return func(jt *jwtToken) {
		jt.verifyKey = verifyKey
	}
}

func NewJWTTokenManager(secret []byte, signMethod jwt.SigningMethod, options ...Option) Manager {
	jt := &jwtToken{
		name:       DefaultIssuerName,
		signKey:    secret,
		signMethod: signMethod,
	}

	for _, opt := range options {
		opt(jt)
	}

	return jt
}
