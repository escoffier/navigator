package idp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/security-rd/go-pkg/logging"
)

// OidcProvider daocloud dx平台
type OidcProvider struct {
	enabled               bool
	discoveryEndpoint     string
	clientID              string
	secretKey             string
	scopes                string
	authorizationEndpoint string
	tokenEndpoint         string
	userinfoEndpoint      string
	endSessionEndpoint    string
	issuer                string
	redisClient           *redis.Client
}

type discoveryConf struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JwksUri                          string   `json:"jwks_uri"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	EndSessionEndpoint               string   `json:"end_session_endpoint"`
	AuditEndpoint                    string   `json:"audit_endpoint"`
	TokenIntrospectionEndpoint       string   `json:"token_introspection_endpoint"`
}

func NewOidcProvider(discoveryEndpoint, clientID, secretKey, scopes string, enabled bool, redisClient *redis.Client) (*OidcProvider, error) {
	if clientID == "" || secretKey == "" {
		return nil, fmt.Errorf("clientID or secretKey is empty")
	}
	if scopes == "" {
		scopes = "openid"
	}

	p := &OidcProvider{
		enabled:           enabled,
		discoveryEndpoint: discoveryEndpoint,
		clientID:          clientID,
		secretKey:         secretKey,
		redisClient:       redisClient,
		scopes:            scopes,
	}

	body, err := requestWithData(http.MethodGet, discoveryEndpoint, nil, nil)
	if err != nil {
		return nil, err
	}

	conf := discoveryConf{}
	if err = json.Unmarshal(body, &conf); err != nil {
		return nil, err
	}

	if conf.AuthorizationEndpoint == "" ||
		conf.TokenEndpoint == "" ||
		conf.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("oidc provider metadata url params error: %v", conf)
	}

	p.authorizationEndpoint = conf.AuthorizationEndpoint
	p.tokenEndpoint = conf.TokenEndpoint
	p.userinfoEndpoint = conf.UserinfoEndpoint
	p.endSessionEndpoint = conf.EndSessionEndpoint
	p.issuer = conf.Issuer
	return p, nil
}

func (p OidcProvider) GetAuthUrl() (string, error) {
	return fmt.Sprintf("%s?response_type=code&client_id=%s&scope=%s", p.authorizationEndpoint, p.clientID, p.scopes), nil
}

func (p OidcProvider) Enabled() bool {
	return p.enabled
}

type getUserInfoPayload struct {
	RedirectUri  string `json:"redirectUri"`
	SessionState string `json:"sessionState"`
	Code         string `json:"code"`
}

type oidcTokenResp struct {
	AccessToken      string `json:"access_token"`
	IdToken          string `json:"id_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`

	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type oidcUserInfoResp struct {
	Sub               string `json:"sub"`
	EmailVerified     bool   `json:"email_verified"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	Language          string `json:"language"`
}

func (p OidcProvider) GetUserInfo(ctx context.Context, raw json.RawMessage) (*IdpUserInfo, error) {
	payload := getUserInfoPayload{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}

	body := fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s", payload.Code, payload.RedirectUri)
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	auth := p.clientID + ":" + p.secretKey
	headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))

	//return nil, errors.New("owen")
	tokenBody, err := requestWithData(http.MethodPost, p.tokenEndpoint, headers, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	resp := oidcTokenResp{}
	if err = json.Unmarshal(tokenBody, &resp); err != nil {
		return nil, err
	}

	if resp.Error != "" {
		return nil, fmt.Errorf("oidc get error: %v %v", resp.Error, resp.ErrorDescription)
	}
	if resp.SessionState != payload.SessionState {
		return nil, fmt.Errorf("session_state is not match: %v %v", resp.SessionState, payload.SessionState)
	}

	headers = map[string]string{
		"Authorization": "Bearer " + resp.AccessToken,
	}
	userBody, err := requestWithData(http.MethodGet, p.userinfoEndpoint, headers, nil)
	if err != nil {
		return nil, err
	}

	oidcUserInfo := oidcUserInfoResp{}
	if err = json.Unmarshal(userBody, &oidcUserInfo); err != nil {
		return nil, err
	}

	// TODO：应该持续续约accessToken
	// dx的accessToken有效期是1天，和我们平台周期一致
	// 所以dx可以不用持续续约accessToken，也能正常使用
	key := getRedisKey(oidcUserInfo.PreferredUsername)
	err = p.redisClient.Set(ctx, key, tokenBody, time.Duration(resp.ExpiresIn)*time.Second).Err()
	if err != nil {
		return nil, err
	}

	return &IdpUserInfo{
		Username: oidcUserInfo.PreferredUsername,
		IDToken:  resp.IdToken,
	}, nil
}

func getRedisKey(username string) string {
	return fmt.Sprintf("%s_accesstoken:%s", ProviderOIDC, username)
}

func (p OidcProvider) Logout(ctx context.Context, username string) error {
	tokenBody, err := p.redisClient.Get(ctx, getRedisKey(username)).Bytes()
	if err != nil {
		return err
	}

	oidcToken := oidcTokenResp{}
	if err = json.Unmarshal(tokenBody, &oidcToken); err != nil {
		return err
	}

	headers := map[string]string{
		"Authorization": "Bearer " + oidcToken.AccessToken,
	}
	resp, err := request(http.MethodPost, p.endSessionEndpoint, headers, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		b, err := io.ReadAll(resp.Body)
		logging.Get().Warn().Msgf("there were some strange errors: %s, %v", string(b), err)
	}

	return nil
}

func (p OidcProvider) WebHook(raw json.RawMessage) error {
	panic("TODO")
}
