package imagesec

import (
	"errors"
	"strings"
	"time"

	"github.com/containerd/containerd/pkg/cri/util"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts/preConsts"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
)

type Registry struct {
	ID              int64  `gorm:"primaryKey" json:"id"`
	Name            string `gorm:"column:name" json:"name"`         // 仓库名字,仓库名是仓库的唯一标识,一个仓库名称  对应一个用户
	RegType         string `gorm:"column:reg_type" json:"regType"`  // 仓库类型
	Url             string `gorm:"column:url" json:"url"`           // 如:docker.io/v2, quay.io/v2
	Username        string `gorm:"column:username" json:"username"` // user for login registry
	Password        []byte `gorm:"column:password" json:"-"`        // DES加密
	PasswordString  string `gorm:"-" json:"password"`
	Description     string `gorm:"column:description"  json:"description"`
	AuthStr         string `gorm:"-" json:"authStr"`                               // 用户名和密码加密后的数据，不存入数据库中
	SyncInterval    int64  `gorm:"column:sync_interval" json:"syncInterval"`       // 单位：分钟
	LastSyncAt      int64  `gorm:"column:last_sync_at" json:"LastSyncAt"`          // 最后一次同步时间(单位：毫秒)
	AccessKey       string `gorm:"column:access_key" json:"accessKey"`             // 阿里云仓库的AccessKey
	AccessSecret    string `gorm:"column:access_secret" json:"accessSecret"`       // 阿里云仓库的AccessSecret
	InstanceID      string `gorm:"column:instance_id" json:"instanceID"`           // 阿里云仓库企业版实例ID
	RegionID        string `gorm:"column:region_id" json:"regionID"`               // 阿里云仓库企业版地域ID
	ScannerInstance string `gorm:"column:scanner_instance" json:"scannerInstance"` // 当前仓库所用扫描器 scan-%s (clusterKey)
	Status          string `gorm:"column:status" json:"status"`                    // 健康状况
	HealthMsg       string `gorm:"column:health_msg" json:"healthMsg"`             // 不健康时的错误信息
	HeatBeat        int64  `gorm:"column:heat_beat" json:"heatBeat"`               // 上一次检查时间

	CreatedAt time.Time `gorm:"autoCreateTime:milli,column:created_at" json:"createdAt"`
	UpdatedAt time.Time `gorm:"autoUpdateTime:milli,column:updated_at" json:"updatedAt"`
	DeletedAt int64     `gorm:"column:deleted_at" json:"deletedAt"`
}

type RegistrySimple struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Url     string `json:"url"`
	RegType string `json:"regType"`
}

func (reg *Registry) Simplify() RegistrySimple {
	return RegistrySimple{Name: reg.Name, Url: reg.Url, RegType: reg.RegType, ID: reg.ID}
}

func (reg *Registry) ToUpdater() map[string]interface{} {
	updater := map[string]interface{}{
		"name": reg.Name,
		// "reg_type":    reg.RegType, // 仓库类型 + 地址不可编辑
		// "url":    reg.Url,
		"scanner_instance": reg.ScannerInstance,
		"username":         reg.Username,
		// "password":         reg.Password,
		"description":   reg.Description,
		"sync_interval": reg.SyncInterval,
		"access_key":    reg.AccessKey,
		"access_secret": reg.AccessSecret,
		"region_id":     reg.RegionID,
		"instance_id":   reg.InstanceID,
	}
	if reg.PasswordString != "" {
		updater["password"] = reg.Password
	}

	return updater
}

func (reg *Registry) WhetherToStartSync() bool {
	if reg.LastSyncAt == 0 {
		return true
	}

	now := time.Now().Unix()

	// 防止长久未同步之后，就一直不同再同步任务了
	if reg.LastSyncAt/1000+reg.SyncInterval*60 < now {
		return true
	}

	return false
}

func (reg *Registry) TableName() string {
	return "ivan_scanner_registries"
}

var regTypeNameKey map[string]LabelValue

func GetRegType() map[string]LabelValue {
	if regTypeNameKey == nil {
		regTypeNameKey = make(map[string]LabelValue)
		regTypeNameKey[AliAcrVersion] = LabelValue{Value: AliAcrVersion, Label: "阿里云 ACR 个人版 (公有云)"}
		regTypeNameKey[AliAcrEEVersion] = LabelValue{Value: AliAcrEEVersion, Label: "阿里云 ACR 企业版 (公有云)"}
		regTypeNameKey[DockerRegistryV2Version] = LabelValue{Value: DockerRegistryV2Version, Label: "Docker Registry (v2)"}
		regTypeNameKey[HarborVersion] = LabelValue{Value: HarborVersion, Label: "Harbor"}
		regTypeNameKey[HaiWeiSwrVersion] = LabelValue{Value: HaiWeiSwrVersion, Label: "华为云 SWR 个人版 (公有云)"}
		regTypeNameKey[HaiWeiSwrENVersion] = LabelValue{Value: HaiWeiSwrENVersion, Label: "华为云 SWR 企业版 (公有云)"}
		regTypeNameKey[JfrogVersion] = LabelValue{Value: JfrogVersion, Label: "JFrog Artifactory"}
	}
	return regTypeNameKey
}

func (reg *Registry) FitHarborVersion() {
	if reg.RegType == HarborV1Version || reg.RegType == HarborV2Version {
		reg.RegType = HarborVersion
	}
}

func (reg *Registry) HidePassword() {
	reg.PasswordString = ""
	reg.AuthStr = ""
}

func (reg *Registry) Check() error {
	if reg.ScannerInstance == "" {
		return i18.CreateI18BadReqErr("未设置扫描器", "not set scan instance")
	}
	return nil
}

func (reg *Registry) Validate(valTY string) error {

	if strings.Trim(reg.Name, " ") == "" {
		return errors.New("no name")
	}
	if strings.Trim(reg.Username, " ") == "" {
		return errors.New("no username")
	}

	if !util.InStringSlice([]string{HarborV1Version, HarborV2Version, HarborVersion}, reg.RegType) {
		if reg.SyncInterval < 5 {
			return errors.New("SyncInterval must be larger than 5 minute")
		}
	}

	if valTY == preConsts.ValidateCreate {
		if reg.Url == "" && len([]rune(reg.Url)) > 255 {
			return errors.New("registry address is illegal")
		}
		if strings.Trim(reg.PasswordString, " ") == "" {
			return errors.New("no password")
		}
	}
	return nil
}
