package imagesec

import (
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 节点元信息
type NodeInfo struct {
	ID          int64  `gorm:"primary_key;AUTO_INCREMENT" json:"id" `
	UniqueID    uint64 `gorm:"column:unique_id" json:"uniqueID,string"` // 生成的ID，写入关联数据时就不用事务
	IP          string `gorm:"column:ip" json:"ip"`                     // 结点的Ip
	Hostname    string `gorm:"column:hostname" json:"hostname"`         // 结点的HostName
	ClusterKey  string `gorm:"column:cluster_key" json:"clusterKey"`
	ClusterName string `gorm:"-" json:"clusterName"` // 集群名
	// 下期功能
	VulnDb     string `gorm:"-"  json:"vulnDb"`
	AviraDB    string `gorm:"-" json:"aviraDB"`
	ClamavDB   string `gorm:"-" json:"clamavDB"`
	WebshellDB string `gorm:"-" json:"webshellDB"`

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *NodeInfo) Same(after *NodeInfo) bool {
	if vi.UniqueID != after.UniqueID {
		return false
	}
	return true
}

func (vi *NodeInfo) LogStr() string {
	ss := fmt.Sprintf("%s-%s-%s", vi.Hostname, vi.ClusterKey, vi.IP)
	return ss
}

func (vi *NodeInfo) TableName() string {
	return "ivan_scan_node_info"
}

func (vi *NodeInfo) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.IP == "" {
		return fmt.Errorf("not get IP")
	}
	if vi.Hostname == "" {
		return fmt.Errorf("not get Hostname")
	}
	if vi.ClusterKey == "" {
		return fmt.Errorf("not get ClusterKey")
	}

	if vi.UniqueID <= 0 {
		vi.UniqueID = vi.GenUniqueID()
	}
	if vi.UniqueID <= 0 {
		return fmt.Errorf("not get uniqueID")
	}
	return nil
}

func (vi *NodeInfo) GenUniqueID() uint64 {
	key := fmt.Sprintf("%s-%s-%s", vi.IP, vi.Hostname, vi.ClusterKey)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

type ScannerInstanceInfo struct {
	ID              int64  `gorm:"id"  json:"id"`
	ClusterKey      string `gorm:"column:cluster_key" json:"clusterKey"`
	ClusterName     string `gorm:"column:cluster_name" json:"clusterName"`
	ScannerPodID    string `gorm:"column:scanner_pod_id" json:"scannerPodID"`      // scanner 启动时生成的UUID,重启动后改变
	ScannerInstance string `gorm:"column:scanner_instance" json:"scannerInstance"` // scanner当前实例，重新启动不会改变
	ScannerVersion  string `gorm:"column:scanner_version" json:"scannerVersion"`   // 扫描器版本号
	HeartBeatAt     int64  `gorm:"column:heart_beat_at" json:"heartBeatAt"`        // 上报的心跳

	// 下期功能
	VulnDb     string `gorm:"-"  json:"vulnDb"`
	AviraDB    string `gorm:"-" json:"aviraDB"`
	ClamavDB   string `gorm:"-" json:"clamavDB"`
	WebshellDB string `gorm:"-" json:"webshellDB"`
}

func (*ScannerInstanceInfo) TableName() string { return "ivan_scanner_instance" }

func (vi *ScannerInstanceInfo) LogStr() string {
	s := fmt.Sprintf("%s-%s", vi.ClusterKey, vi.ClusterName)
	return s
}

func (vi *ScannerInstanceInfo) Same(info ScannerInstanceInfo) bool {
	return vi.ClusterKey == info.ClusterKey &&
		vi.ClusterName == info.ClusterName &&
		vi.ScannerPodID == info.ScannerPodID &&
		vi.ScannerInstance == info.ScannerInstance
}

func (vi *ScannerInstanceInfo) ToUpdater() map[string]interface{} {
	updater := map[string]interface{}{
		"cluster_key":      vi.ClusterKey,
		"cluster_name":     vi.ClusterName,
		"scanner_instance": vi.ScannerInstance,
		"scanner_pod_id":   vi.ScannerPodID,
		"heart_beat_at":    time.Now().Unix(),
	}
	return updater
}

func (vi *ScannerInstanceInfo) ToHeartBeatAt() map[string]interface{} {
	updater := map[string]interface{}{
		"heart_beat_at":   time.Now().Unix(),
		"scanner_version": vi.ScannerVersion,
	}
	return updater
}

type ScanInstanceParam struct {
	ScannerInstance string
}
