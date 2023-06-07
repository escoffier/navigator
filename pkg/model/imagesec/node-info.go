package imagesec

import (
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 节点元信息
type NodeInfo struct {
	ID          int64  `gorm:"primary_key;AUTO_INCREMENT" json:"id" `
	UniqueID    uint64 `gorm:"column:unique_id" json:"uniqueID,string"` // 生成的ID，写入关联数据时就不用事务
	IP          string `gorm:"column:ip" json:"ip"`                     // 结点的Ip
	Hostname    string `gorm:"column:hostname" json:"hostname"`         // 结点的HostName
	ClusterKey  string `gorm:"column:cluster_key" json:"clusterKey"`
	ClusterName string `gorm:"-" json:"clusterName"`                                    // 集群名
	CreatedAt   int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt   int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
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
	return util.GenerateUUID64(key)
}
