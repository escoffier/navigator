package configs

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/data"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/naviaudit"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"time"
)

const (
	ConfigDomainPlatformUser = "platformUser"

	ConfigDomainMicroseg = "microseg"

	ConfigDomainData       = "data"
	ConfigDomainUserCenter = "usercenter"
	ConfigDomainNaviAudit  = "naviaudit"

	StatusWait      = "wait"
	StatusImporting = "backup"
	StatusSuccess   = "success"
	StatusFailed    = "failed"
)

var key = []byte("abcdefghijklmnop")
var instance Configs

type Configs struct {
	status          bool // 状态，表示是否在锁定 , true :锁定状态
	aeskey          []byte
	rdb             *databases.RDBInstance
	configOperators map[string]ConfigOperator
	operatorStatus  *OperatorStatus
	Aperator        string
}

// wait:等待备份； backup:备份中； success：备份成功; failed:备份失败
type OperatorStatus struct {
	Status   string
	Operator map[string]string
}

func (c *Configs) GetDB() *databases.RDBInstance {
	return c.rdb
}
func (c *Configs) GetConfigsStatus() bool {
	return c.status
}
func (c *Configs) GetConfigOperator() map[string]ConfigOperator {
	return c.configOperators
}
func (c *Configs) GetAesKey() []byte {
	return c.aeskey
}
func (c *Configs) GetOperatorStatus() map[string]string {
	return c.operatorStatus.Operator
}
func (c *Configs) GetImportStatus() string {
	return c.operatorStatus.Status
}
func (c *Configs) SetOperatorStatus(statusList *OperatorStatus) {
	c.operatorStatus = statusList
}
func (c *Configs) GetAperator() string {
	return c.Aperator
}
func (c *Configs) SetAperator(username string) {
	c.Aperator = username
}

func Init(rdb *databases.RDBInstance, redisClient *redis.Client) error {
	ConfigOperators, err := initConfigOperator(rdb, redisClient)
	instance = Configs{
		rdb:             rdb,
		configOperators: ConfigOperators,
		aeskey:          key,
		status:          false,
		operatorStatus:  &OperatorStatus{},
	}
	return err
}

func GetService() *Configs {
	return &instance
}

type ConfigOperator interface {
	Export(ctx context.Context) ([]byte, error)
	Import(ctx context.Context, config []byte) error
	SetAperator(username string)
}

func initConfigOperator(rdb *databases.RDBInstance, redisClient *redis.Client) (map[string]ConfigOperator, error) {
	// data
	ctx := context.Background()
	dataService, ok := data.GetService(ctx)
	if !ok {
		logging.Get().Error().Msgf("platform_data service not ready")
		return nil, errors.New("platform_data service not ready")
	}

	naviAduitservice, ok := naviaudit.GetService()
	if !ok {
		logging.Get().Error().Msgf("navi_audit service not ready")
		return nil, errors.New("navi_audit service not ready")
	}

	return map[string]ConfigOperator{
		// user
		ConfigDomainPlatformUser: &UserOperator{rdb: rdb},

		// microseg
		ConfigDomainMicroseg: &MicroSegOperator{rdb: rdb},

		// platform
		ConfigDomainData:       &DataConfigOperator{dataService: dataService},
		ConfigDomainUserCenter: &UsercentorConfigOperator{rdb: rdb, redisClient: redisClient},
		ConfigDomainNaviAudit:  &NaviauditConfigOperator{naviService: naviAduitservice},
	}, nil

}

// importConf
func (c *Configs) ImportRun(Conf map[string][]byte) error {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, defaultAccountTimeout)
	defer cancel()

	c.status = true

	var operatorList []string
	operatorStatus := OperatorStatus{
		Operator: map[string]string{},
	}
	if err := json.Unmarshal(Conf["operator"], &operatorList); err != nil {
		return err
	}
	delete(Conf, "operator")

	for _, value := range operatorList {
		operatorStatus.Operator[value] = StatusWait
	}
	c.SetOperatorStatus(&operatorStatus)

	time.Sleep(time.Second * 3)

	cos := c.configOperators
	err := cos[ConfigDomainPlatformUser].Import(ctx, Conf[ConfigDomainPlatformUser])
	if err != nil {
		logging.Get().Log().Msgf("err :", err)
		c.status = false
		return err
	}
	for _, value := range operatorList {
		if config, ok := Conf[value]; ok {
			if co, ok := cos[value]; ok {
				co.SetAperator(c.GetAperator())
				c.operatorStatus.Operator[value] = StatusImporting

				time.Sleep(time.Second * 1)

				err := co.Import(ctx, config)
				if err != nil {
					logging.Get().Log().Msgf("err :", err)
					c.operatorStatus.Operator[value] = StatusFailed
				} else {
					c.operatorStatus.Operator[value] = StatusSuccess
				}
			} else {
				logging.Get().Error().Err(errors.New("config service not add " + value + "  module ")).Msg("")
			}
		} else {
			logging.Get().Error().Err(errors.New("not find " + value + " module`s config")).Msg("")
		}
	}

	// backup end
	c.operatorStatus.Status = "success"
	c.status = false
	return nil
}
