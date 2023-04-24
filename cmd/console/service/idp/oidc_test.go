package idp

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"testing"

	"github.com/go-redis/redismock/v8"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestOidcProvider(t *testing.T) {
	// mock http
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterRegexpResponder(http.MethodGet, regexp.MustCompile("/\\.well-known/openid-configuration$"),
		httpmock.NewStringResponder(http.StatusOK, `{
"token_endpoint": "https://fake.com/api/v1/oidc/token",
"userinfo_endpoint": "https://fake.com/api/v1/oidc/userinfo",
"end_session_endpoint": "https://fake.com/api/v1/oidc/logout"
}`))

	tokenBody, err := json.Marshal(oidcTokenResp{
		AccessToken:      "fake",
		IdToken:          "fake",
		ExpiresIn:        0,
		RefreshExpiresIn: 0,
		RefreshToken:     "fake",
		TokenType:        "fake",
		NotBeforePolicy:  0,
		SessionState:     "fake",
		Scope:            "fake",
	})
	assert.NoError(t, err)
	httpmock.RegisterRegexpResponder(http.MethodPost, regexp.MustCompile("/api/v1/oidc/token$"),
		httpmock.NewBytesResponder(http.StatusOK, tokenBody))

	userInfoBody, err := json.Marshal(oidcUserInfoResp{
		Sub:               "fake",
		EmailVerified:     false,
		PreferredUsername: "fake",
		Email:             "fake",
		Language:          "fake",
	})
	assert.NoError(t, err)
	httpmock.RegisterRegexpResponder(http.MethodPost, regexp.MustCompile("/api/v1/oidc/userinfo$"),
		httpmock.NewBytesResponder(http.StatusOK, userInfoBody))

	httpmock.RegisterRegexpResponder(http.MethodPost, regexp.MustCompile("/api/v1/oidc/logout$"),
		httpmock.NewBytesResponder(http.StatusNoContent, nil))

	// mock redis
	redisClient, redisMock := redismock.NewClientMock()
	redisMock.ExpectSet(getRedisKey("fake"), tokenBody, 0).SetVal("0")
	redisMock.ExpectGet(getRedisKey("fake")).SetVal(string(tokenBody))

	// test new
	p, err := NewOidcProvider("https://fake.com", "fake", "fake", "", true, redisClient)
	assert.NoError(t, err)

	payload := getUserInfoPayload{
		RedirectUri:  "fake",
		SessionState: "fake",
		Code:         "fake",
	}
	b, err := json.Marshal(payload)
	assert.NoError(t, err)

	// test get userinfo
	ret, err := p.GetUserInfo(context.Background(), b)
	assert.NoError(t, err)
	assert.Equal(t, ret.Username, "fake")

	// test logout
	err = p.Logout(context.Background(), "fake")
	assert.NoError(t, err)
}
