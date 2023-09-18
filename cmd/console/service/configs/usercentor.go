package configs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/idp"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/session"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	"net/http"
	"os"
	"time"
)

const (
	defaultAccountTimeout = time.Second * 60
)

var (
	CheckLdapGroupInterError = errors.New("checkLdapGroup internal error")
)

type loginConfigInfo struct {
	FirstLoginChangePwd bool     `json:"firstLoginChangePwd"` // 首次登录修改密码
	ResetLoginChangePwd bool     `json:"resetLoginChangePwd"` // 管理员重置密码后首次修改密码
	CycleChangePwd      bool     `json:"cycleChangePwd"`      // 周期更换密码
	CycleDay            int      `json:"cycleDay"`            // 最小1天
	RateLimitEnable     bool     `json:"rateLimitEnable"`     // enable  账号锁定机制
	RateLimitThreshold  int32    `json:"rateLimitThreshold"`  // 最小1天
	MfaVerityLogin      bool     `json:"mfaVerityLogin"`      // 登录时，mfa认证开启
	PwdSecurityLevel    string   `json:"PwdSecurityLevel"`    // 密码强度，修改密码时使用 ，分为 非常强，强，易班，弱
	IPBlackList         []string `json:"iPBlackList"`         // ip黑名单
}

type UsercentorConfigOperator struct {
	rdb         *databases.RDBInstance
	redisClient *redis.Client
	Aperator    string
}

func (c *UsercentorConfigOperator) GetAperator() string {
	return c.Aperator
}

func (c *UsercentorConfigOperator) SetAperator(username string) {
	c.Aperator = username
}

type UcOperator struct {
	OperatorConfig []byte
	Status         bool
}

func (uco *UsercentorConfigOperator) Export(ctx context.Context) ([]byte, error) {
	type Conf struct {
		Config map[string][]byte
		Status bool
	}
	config := make(map[string][]byte)

	err := uco.rdb.Get().Transaction(func(tx *gorm.DB) error {
		loginConf, err := ExportLoginConfig(ctx, tx)
		if err != nil {
			return err
		}
		config["login"] = loginConf
		// idp
		idpConf, err := ExportIdpConfig(ctx, tx)
		if err != nil {
			return err
		}
		config["idp"] = idpConf

		// ldap
		jsonldap, err := ExportLdapConf(ctx, tx)
		if err != nil {
			return err
		}
		config["ldap"] = jsonldap

		// radius
		radiusConf, err := ExportRadiusConf(ctx, tx)
		if err != nil {
			return err
		}
		config["radius"] = radiusConf

		return nil
	})
	if err != nil {
		return nil, err
	}

	conf := Conf{
		Config: config,
	}

	jsondata, err := json.Marshal(conf)
	if err != nil {
		logging.Get().Error().Msgf("couldn't get data tll: %w", err)
		return nil, fmt.Errorf("json.Marshal: %w", err)
	}

	return jsondata, nil
}

func (uco *UsercentorConfigOperator) Import(ctx context.Context, config []byte) error {
	type Conf struct {
		Config map[string][]byte
	}

	var configs Conf
	if err := json.Unmarshal(config, &configs); err != nil {
		return fmt.Errorf("json.Unmarshal: %w", err)
	}

	err := uco.rdb.Get().Transaction(func(tx *gorm.DB) error {

		for key, value := range configs.Config {
			switch key {
			case "login":
				err := uco.ImportLoginConfig(ctx, value, tx)
				if err != nil {
					return fmt.Errorf("couldn't import login: %w", err)
				}
			case "idp":
				err := uco.ImportIdpConfig(ctx, value, tx)
				if err != nil {
					return fmt.Errorf("couldn't import idp: %w", err)
				}
			case "ldap":
				err := uco.ImportLdapConf(ctx, value, tx)
				if err != nil {
					return fmt.Errorf("couldn't import ldap: %w", err)
				}
			case "radius":
				err := uco.ImportRadiusConf(ctx, value, tx)
				if err != nil {
					return fmt.Errorf("couldn't import radius: %w", err)
				}
			}

		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

// login
func ExportLoginConfig(ctx context.Context, db *gorm.DB) ([]byte, error) {
	Config := UcOperator{
		Status: true,
	}
	loginConf, err := dal.GetConfig(ctx, db, model.ConfLogin)
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("get login config failed: %w", err)
	}

	if err == gorm.ErrRecordNotFound {
		Config.Status = false
	} else {
		Config.OperatorConfig = loginConf.Config
	}

	jsonConfig, err := json.Marshal(Config)
	if err != nil {
		return nil, err
	}
	return jsonConfig, nil
}

func (uco *UsercentorConfigOperator) ImportLoginConfig(ctx context.Context, data []byte, db *gorm.DB) (err error) {
	config := UcOperator{}
	if err = json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("json.Unmarshal: %w", err)
	}
	if !config.Status {
		return dal.DeleteConfig(ctx, db, model.ConfLogin)
	}

	loginConfInfo := loginConfigInfo{}
	if err = json.Unmarshal(config.OperatorConfig, &loginConfInfo); err != nil {
		return fmt.Errorf("json.Unmarshal: %w", err)
	}

	// set login Config
	err = db.Transaction(func(tx *gorm.DB) error {
		// save in mysql
		err = dal.SetConfig(ctx, tx, model.ConfLogin, config.OperatorConfig)
		if err != nil {
			return apperror.NewAnError(http.StatusInternalServerError,
				fmt.Errorf("set config failed: %w", err))
		}

		sessionService, ok := session.GetService()
		if !ok {
			return ErrServiceNotReady
		}
		// 删除redis中的信息
		if err = sessionService.DelLoginConf(ctx); err != nil {
			apperror.NewAnError(http.StatusInternalServerError,
				fmt.Errorf("delete loginConf failed: %w", err))
		}

		// 开启【周期更换登录密码】功能，重置所有用户的上次修改密码时间
		if loginConfInfo.CycleChangePwd {
			err = dal.UpdateUserPasswordToNow(ctx, uco.rdb.Get())
			if err != nil {
				return apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("reset password failed: %w", err))
			}
		}

		// 关闭mfa认证的时候，需要将所有用户的密钥字段数据删除
		if !loginConfInfo.MfaVerityLogin {
			err = dal.DeleteUserMfaSecret(ctx, uco.rdb.Get())
			if err != nil {
				return apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("delete mfasecret failed: %w", err))
			}
		}

		// 删除redis中黑名单信息
		if err = sessionService.DelBlackList(ctx); err != nil {
			apperror.NewAnError(http.StatusInternalServerError,
				fmt.Errorf("delete ipBlackList failed: %w", err))
		}
		return nil
	})
	if err != nil {
		return
	}
	return nil
}

// idp
func ExportIdpConfig(ctx context.Context, db *gorm.DB) ([]byte, error) {
	IdpConfig := UcOperator{Status: true}
	idp := idp.LoginConfig{}

	idpConf, err := dal.GetConfig(ctx, db, model.ConfIdpLogin)
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("get idp config failed: %w", err)
	}
	if err == gorm.ErrRecordNotFound {
		IdpConfig.Status = false
	} else {
		if err = json.Unmarshal(idpConf.Config, &idp); err != nil {
			return nil, fmt.Errorf("unmarshal json failed: %w", err)
		}

		modules, err := dal.GetAllModules(ctx, db)
		if err != nil {
			return nil, err
		}

		modulesSet := map[int]*model.ModuleGroup{}
		for i, v := range modules {
			modulesSet[v.Id] = modules[i]
		}

		for i, v := range idp.DefaultAuth {
			if m, ok := modulesSet[v.Id]; ok {
				idp.DefaultAuth[i] = *m
			}
		}

		for i, p := range idp.PermissionMapping {
			for j, v := range p.Auth {
				if m, ok := modulesSet[v.Id]; ok {
					idp.PermissionMapping[i].Auth[j] = *m
				}
			}
		}
		jsondata, err := json.Marshal(idp)
		if err != nil {
			return nil, err
		}
		IdpConfig.OperatorConfig = jsondata
	}

	jsonConfig, err := json.Marshal(IdpConfig)
	if err != nil {
		return nil, err
	}
	return jsonConfig, nil

}

func (uco *UsercentorConfigOperator) ImportIdpConfig(ctx context.Context, config []byte, db *gorm.DB) error {
	ctx, cancel := context.WithTimeout(ctx, defaultAccountTimeout)
	defer cancel()

	IdpConfig := UcOperator{}
	if err := json.Unmarshal(config, &IdpConfig); err != nil {
		return fmt.Errorf("failed to decode json: %w", err)
	}
	if !IdpConfig.Status {
		return dal.DeleteConfig(ctx, db, model.ConfIdpLogin)
	}

	req := idp.LoginConfig{}
	if err := json.Unmarshal(IdpConfig.OperatorConfig, &req); err != nil {
		return fmt.Errorf("failed to decode json: %w", err)
	}
	logging.Get().Debug().Msgf("get the idp configInfo : %v", req)

	// 默认一些参数
	if req.Platform = os.Getenv(idp.EnvIdpPlatform); req.Platform == "" {
		req.Platform = idp.DxPlatform
	}
	req.IdpProvider = idp.ProviderOIDC
	req.Scopes = "openid+profile+email"
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		if err = idp.NewProviderAndRegister(&req, uco.redisClient); err != nil {
			return apperror.NewCommonError(http.StatusBadRequest,
				fmt.Errorf("update idp config error: %w", err),
				"更新idp配置错误", "update idp config error")
		}

		if err = dal.SetConfig(ctx, tx, model.ConfIdpLogin, body); err != nil {
			return apperror.NewAnError(http.StatusInternalServerError,
				fmt.Errorf("set config failed: %w", err))
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// ldap
func ExportLdapConf(ctx context.Context, db *gorm.DB) ([]byte, error) {
	Config := UcOperator{
		Status: true,
	}

	ldapConf, err := dal.GetConfig(ctx, db, model.LdapConfKey)
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("get ldap config failed: %w", err)
	}

	if err == gorm.ErrRecordNotFound {
		Config.Status = false
	} else {
		groups, err := dal.GetLdapGroupList(ctx, db, 0, 0)
		if err != nil {
			return nil, fmt.Errorf("get ldap config failed: %w", err)
		}
		jsongroup, err := json.Marshal(groups)
		if err != nil {
			return nil, fmt.Errorf("marshal ldapgroup list failed: %w", err)
		}
		ldap := map[string][]byte{
			"ldapConf": ldapConf.Config,
			"groups":   jsongroup,
		}
		jsonldap, err := json.Marshal(ldap)
		if err != nil {
			return nil, fmt.Errorf("marshal ldapConf failed: %w", err)
		}
		Config.OperatorConfig = jsonldap
	}

	jsonConfig, err := json.Marshal(Config)
	if err != nil {
		return nil, err
	}
	return jsonConfig, nil
}

func (uco *UsercentorConfigOperator) ImportLdapConf(ctx context.Context, config []byte, tx *gorm.DB) error {
	ctx, cancel := context.WithTimeout(ctx, defaultAccountTimeout)
	defer cancel()
	Config := UcOperator{}
	ldap := make(map[string][]byte)
	if err := json.Unmarshal(config, &Config); err != nil {
		return fmt.Errorf("failed to decode json: %w", err)
	}
	if !Config.Status {
		return dal.DeleteConfig(ctx, tx, model.LdapConfKey)
	}

	if err := json.Unmarshal(Config.OperatorConfig, &ldap); err != nil {
		return fmt.Errorf("failed to decode json: %w", err)
	}

	err := dal.SetConfig(ctx, tx, model.LdapConfKey, ldap["ldapConf"])
	if err != nil {
		return err
	}

	// 由于这个表的记录量应该特别小而且操作频率特别低，直接清空重写。
	err = uco.truncateLdapGroup(ctx, tx)
	if err != nil {
		return err
	}

	var groups []*model.LdapGroup
	if err := json.Unmarshal(ldap["groups"], &groups); err != nil {
		return err
	}

	for _, value := range groups {
		if err = dal.CreateLdapGroup(ctx, tx, value); err != nil {
			return err
		}
	}

	return nil
}

func (uco *UsercentorConfigOperator) truncateLdapGroup(ctx context.Context, db *gorm.DB) error {
	return dal.TruncateLdapGroup(ctx, db)
}

// radius
func ExportRadiusConf(ctx context.Context, db *gorm.DB) ([]byte, error) {
	radiusConfig := UcOperator{}
	radiusConf, err := dal.GetConfig(ctx, db, model.RadiusConfKey)
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("get config failed: %w", err)
	}
	if err == gorm.ErrRecordNotFound {
		radiusConfig.Status = false
	} else {
		radiusConfig.Status = true
		radiusConfig.OperatorConfig = radiusConf.Config
	}
	jsonConf, err := json.Marshal(radiusConfig)
	if err != nil {
		return nil, err
	}
	return jsonConf, nil
}

func (api *UsercentorConfigOperator) ImportRadiusConf(ctx context.Context, config []byte, db *gorm.DB) error {
	ctx, cancel := context.WithTimeout(ctx, defaultAccountTimeout)
	defer cancel()
	RadiusConfig := UcOperator{}
	if err := json.Unmarshal(config, &RadiusConfig); err != nil {
		return fmt.Errorf("failed to decode json: %w", err)
	}

	if !RadiusConfig.Status {
		return dal.DeleteConfig(ctx, db, model.RadiusConfKey)
	}

	err := dal.SetConfig(ctx, db, model.RadiusConfKey, RadiusConfig.OperatorConfig)
	if err != nil {
		return err
	}

	return nil
}
