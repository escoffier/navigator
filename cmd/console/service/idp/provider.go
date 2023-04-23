package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
)

const (
	ProviderOIDC = "oidc"

	DxPlatform     = "dx"
	EnvIdpPlatform = "TENSOR_IDP_PLATFORM"
)

type SsoPermissionMappingItem struct {
	Name     string              `json:"name"`
	RoleName string              `json:"roleName"`
	Auth     []model.ModuleGroup `json:"auth"`
}

type LoginConfig struct {
	Enabled           bool                       `json:"enabled"`
	Platform          string                     `json:"platform"`
	IdpProvider       string                     `json:"idpProvider"`
	DefaultAuth       []model.ModuleGroup        `json:"defaultAuth"`
	DiscoveryEndpoint string                     `json:"discoveryEndpoint"`
	ClientID          string                     `json:"clientId"`
	ClientSecret      string                     `json:"clientSecret"`
	Scopes            string                     `json:"scopes"`
	PermissionMapping []SsoPermissionMappingItem `json:"permissionMapping"`
}

type IdpUserInfo struct {
	Username string
	Role     string
	IDToken  string
}

type Provider interface {
	GetAuthUrl() (string, error)
	GetUserInfo(ctx context.Context, raw json.RawMessage) (*IdpUserInfo, error)
	Logout(ctx context.Context, username string) error
}

var (
	providerManager = map[string]Provider{}
	rwMutex         sync.RWMutex
)

func InitIdpLogin(rdb *databases.RDBInstance, redisClient *redis.Client) error {
	conf, err := dal.GetConfig(context.Background(), rdb.GetReadDB(), model.ConfIdpLogin)
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			logging.Get().Error().Err(err).Msg("")
			return err
		}

		return nil
	}

	idpConf := LoginConfig{}
	if err = json.Unmarshal(conf.Config, &idpConf); err != nil {
		logging.Get().Error().Err(err).Msg("")
		return err
	}

	if !idpConf.Enabled {
		return nil
	}

	return NewProviderAndRegister(&idpConf, redisClient)
}

func NewProviderAndRegister(idpConf *LoginConfig, redisClient *redis.Client) error {
	var p Provider
	switch idpConf.IdpProvider {
	case ProviderOIDC:
		var err error
		p, err = NewOidcProvider(idpConf.DiscoveryEndpoint, idpConf.ClientID, idpConf.ClientSecret, idpConf.Scopes, redisClient)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknowm idp provider: %s", idpConf.Platform)
	}

	logging.Get().Debug().Msgf("register provider %s", idpConf.Platform)
	return RegisterProvider(idpConf.Platform, p)
}

func RegisterProvider(platform string, p Provider) error {
	if p == nil {
		return fmt.Errorf("provider is nil")
	}

	rwMutex.Lock()
	providerManager[platform] = p
	rwMutex.Unlock()
	return nil
}

func GetProvider(platform string) (Provider, error) {
	rwMutex.RLock()
	defer rwMutex.RUnlock()

	if p, ok := providerManager[platform]; ok {
		return p, nil
	}

	return nil, fmt.Errorf("unsupport platform: %s", platform)
}
