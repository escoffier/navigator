package model

import (
	"database/sql/driver"

	json "github.com/json-iterator/go"
)

type BaitService struct {
	TableBase
	Name           string `json:"name" gorm:"column:name"`
	BaitName       string `json:"baitName" gorm:"column:bait_name"`
	BaitId         uint32 `json:"baitId" gorm:"column:bait_id"`
	ClusterKey     string `json:"clusterKey" gorm:"column:cluster_key"`
	Namespace      string `json:"namespace" gorm:"column:namespace"`
	ResourceName   string `json:"resourceName" gorm:"column:resource_name"`
	Prefix         string `json:"prefix" gorm:"column:prefix"`
	Image          string `json:"image" gorm:"column:image"`
	RegistryId     int    `json:"registryId" gorm:"column:registry_id"`
	WorkLoadStatus string `json:"workLoadStatus" gorm:"column:workload_status"`
	HaveAlerts     bool   `json:"haveAlerts" gorm:"column:have_alerts"`
	Replica        int32  `json:"replica,omitempty" gorm:"column:replica"`
	OutboundOff    bool   `json:"outboundOff,omitempty" gorm:"column:outbound_off"`
}

func (BaitService) TableName() string {
	return "ivan_bait_services"
}

type ServerPorts []int32

func (m *ServerPorts) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &m)
}

func (m *ServerPorts) Value() (driver.Value, error) {
	return json.Marshal(m)
}

type BaitImages struct {
	TableBase
	Name          string      `json:"name" gorm:"column:name"`
	BaitName      string      `json:"baitName" gorm:"column:bait_name"`
	Ports         ServerPorts `gorm:"column:ports;type:varchar(512)"`
	Vulnerability string      `json:"vulnerability" gorm:"column:vulnerability"`
	Description   string      `json:"description" gorm:"column:description"`
	EventPrefix   string      `json:"eventPrefix" gorm:"column:event_prefix"`
}

func (BaitImages) TableName() string {
	return "ivan_bait_images"
}
