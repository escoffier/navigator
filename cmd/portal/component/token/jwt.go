package token

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	portal "gitlab.com/piccolo_su/vegeta/cmd/portal/model"
)

const (
	DefaultIssuerName = "Portal"
	DefaultSecret     = "Portal-Secret"
)

type Claims struct {
	Payload
	// Currently, we are not using any field in jwt.StandardClaims
	jwt.RegisteredClaims
}

var jwtTokenMa *jwtToken

type jwtToken struct {
	name       string
	signKey    []byte
	verifyKey  []byte
	signMethod jwt.SigningMethod
	expiry     int64        // 多少秒后过期
	mu         sync.RWMutex // 用于保护 tokenStore 的并发访问
	UserDal    UserDal
}

func (jt *jwtToken) Verify(tokenString string) (Payload, error) {
	ctx := context.Background()
	clm := Claims{}
	if tokenString == "" {
		return clm.Payload, fmt.Errorf("not get token")
	}
	_, err := jwt.ParseWithClaims(tokenString, &clm, jt.keyFunc)
	if err != nil {
		return clm.Payload, fmt.Errorf("can not parse token")
	}
	p := clm.Payload
	if p.PortalEmail == "" {
		return clm.Payload, fmt.Errorf("not get user")
	}
	user, err := jt.UserDal.GetUser(ctx, portal.SearchUserParam{ID: p.ID, PortalEmail: p.PortalEmail})
	if err != nil {
		return clm.Payload, fmt.Errorf("can not valid token")
	}
	ut := strings.TrimSpace(strings.ReplaceAll(user.Token, "Bearer ", ""))
	to := strings.TrimSpace(strings.ReplaceAll(tokenString, "Bearer ", ""))
	if ut != to {
		return clm.Payload, fmt.Errorf("the user login on other device")
	}
	if user.TokenExpAt < time.Now().Unix() {
		return p, fmt.Errorf("token expired")
	}
	up := map[string]interface{}{
		"token_exp_at": time.Now().Unix() + jt.expiry,
	}
	_ = jt.UserDal.UpdateUser(ctx, portal.UpdateUserParam{ID: p.ID, Updater: up})

	return clm.Payload, nil
}

func (jt *jwtToken) Exp() int64 {
	return jt.expiry
}

func (jt *jwtToken) IssueTo(payload Payload) (string, error) {
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

	token := jwt.NewWithClaims(jt.signMethod, clm)

	tokenString, err := token.SignedString(jt.signKey)
	if err != nil {
		return "", err
	}
	tokenString = "Bearer " + tokenString

	return tokenString, nil
}

func (jt *jwtToken) keyFunc(t *jwt.Token) (interface{}, error) {
	if jt.verifyKey != nil {
		return jt.verifyKey, nil
	} else {
		return jt.signKey, nil
	}
}

func (jt *jwtToken) Parse(to string) (Payload, error) {
	clm := Claims{}
	// verify token signature and expiration time
	_, err := jwt.ParseWithClaims(to, &clm, jt.keyFunc)
	if err != nil {
		return clm.Payload, err
	}

	return clm.Payload, nil
}

type Option func(o *jwtToken)

func SetVerifyKey(verifyKey []byte) Option {
	return func(jt *jwtToken) {
		jt.verifyKey = verifyKey
	}
}
func SetExpiry(expiry int64) Option {
	return func(jt *jwtToken) {
		jt.expiry = expiry
	}
}

func SetUserDal(d UserDal) Option {
	return func(o *jwtToken) {
		o.UserDal = d
	}
}

func NewJWTTokenManager(dal UserDal, options ...Option) Manager {
	if jwtTokenMa != nil {
		return jwtTokenMa
	}

	jt := &jwtToken{
		name:       DefaultIssuerName,
		signKey:    []byte(DefaultSecret),
		verifyKey:  nil,
		UserDal:    dal,
		signMethod: jwt.SigningMethodHS256,
		mu:         sync.RWMutex{},
		expiry:     60 * 60, // 一个小时
	}
	for _, opt := range options {
		opt(jt)
	}
	jwtTokenMa = jt
	return jt
}
