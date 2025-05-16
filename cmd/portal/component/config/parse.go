package config

import (
	"fmt"
	"os"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gopkg.in/yaml.v2"
)

var gob *Config

// Config 表示整个应用程序的配置
type Config struct {
	Portal      Portal      `yaml:"portal"`
	SourceCheck SourceCheck `yaml:"sourceCheck"`
	CodeSec     CodeSec     `yaml:"codeSec"`
	Tensor      Tensor      `yaml:"tensor"`
}

// Portal 配置部分
type Portal struct {
	Addr          string `yaml:"addr"`
	LogLevel      string `yaml:"logLevel"`
	AdminEmail    string `yaml:"adminEmail"`
	AdminPassword string `yaml:"adminPassword"`
}

type Tensor struct {
	Addr  string `yaml:"addr"`
	Email string `yaml:"email"`
	Pwd   string `yaml:"pwd"`
}

// SourceCheck 配置部分
type SourceCheck struct {
	Addr      string    `yaml:"addr"`
	AdminUser CheckUser `yaml:"adminUser"`
	OrgUser   CheckUser `yaml:"orgUser"`
}

// CheckUser SourceCheck 用户配置
type CheckUser struct {
	Email    string `yaml:"email"`
	Password string `yaml:"password"`
	Token    string `yaml:"token"`
	UserUUID string `yaml:"user_uuid"`
}

// CodeSec 配置部分
type CodeSec struct {
	Addr      string  `yaml:"addr"`
	AdminUser SecUser `yaml:"adminUser"`
	OrgUser   SecUser `yaml:"orgUser"`
	TeamUser  SecUser `yaml:"teamUser"`
}

// SecUser CodeSec 用户配置
type SecUser struct {
	Email        string `yaml:"email"`
	Password     string `yaml:"password"`
	AccessKey    string `yaml:"accessKey"`
	AccessSecret string `yaml:"accessSecret"`
}

func ParseConfig(path string) (*Config, error) {
	logging.GetLogger().Info().Str("configPath", path).Msg("ParseConfig")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		logging.GetLogger().Err(err).Str("configPath", path).Msg("ParseConfig")
		return nil, err
	}
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	gob = cfg

	return cfg, nil
}

// Check 验证配置是否有效，返回检查结果和错误信息
func (c *Config) Check() error {
	var missingFields []string

	// 检查 Portal 配置
	if c.Portal.Addr == "" {
		missingFields = append(missingFields, "portal.addr")
	}
	if c.Portal.LogLevel == "" {
		c.Portal.LogLevel = "info"
	}

	if c.Portal.AdminPassword == "" {
		missingFields = append(missingFields, "portal.AdminPassword")
	}

	// 检查 SourceCheck 配置
	if c.SourceCheck.Addr == "" {
		missingFields = append(missingFields, "sourceCheck.addr")
	}

	// 检查 SourceCheck OrgUser
	if c.SourceCheck.OrgUser.Email == "" {
		missingFields = append(missingFields, "sourceCheck.orgUser.username")
	}
	if c.SourceCheck.OrgUser.Password == "" {
		missingFields = append(missingFields, "sourceCheck.orgUser.password")
	}
	if c.SourceCheck.OrgUser.Token == "" {
		missingFields = append(missingFields, "sourceCheck.orgUser.token")
	}

	// 检查 CodeSec 配置
	if c.CodeSec.Addr == "" {
		missingFields = append(missingFields, "codeSec.addr")
	}

	// 检查 CodeSec OrgUser
	if c.CodeSec.OrgUser.Email == "" {
		missingFields = append(missingFields, "codeSec.orgUser.username")
	}
	if c.CodeSec.OrgUser.Password == "" {
		missingFields = append(missingFields, "codeSec.orgUser.password")
	}
	if c.CodeSec.OrgUser.AccessKey == "" {
		missingFields = append(missingFields, "codeSec.orgUser.accessKey")
	}
	if c.CodeSec.OrgUser.AccessSecret == "" {
		missingFields = append(missingFields, "codeSec.orgUser.accessSecret")
	}
	if c.Tensor.Addr == "" {
		missingFields = append(missingFields, "tensor.addr")
	}
	if c.Tensor.Email == "" {
		missingFields = append(missingFields, "tensor.email")
	}
	if c.Tensor.Pwd == "" {
		missingFields = append(missingFields, "tensor.pwd")
	}

	if len(missingFields) > 0 {
		return fmt.Errorf("config has empte filed: %v", missingFields)
	}

	return nil
}

func GetConfig() *Config {
	return gob
}
