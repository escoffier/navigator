package imagesec

import (
	"fmt"
)

type ScanInstance struct {
	ClusterKey      string `json:"clusterKey"`
	ClusterName     string `json:"clusterName"`
	ScannerPodID    string `json:"scannerPodID"`    // scanner当前Pod，重新启动改变
	ScannerInstance string `json:"scannerInstance"` // scanner当前实例，重新启动不会改变
	ScannerVersion  string `json:"scannerVersion"`  // 扫描器版本号
}

type ScanImageMeta struct {
	UniqueID  uint64 `json:"uniqueID"`
	ImageUUID uint32 `json:"imageUUID"`
	Host      string `json:"host"`
	Digest    string `json:"digest"`
	Repo      string `json:"repo"`
	Tag       string `json:"tag"`
}

func (vi *ScanImageMeta) ImageName() string {
	return fmt.Sprintf("%s/%s:%s", vi.Host, vi.Repo, vi.Tag)
}

// NodeInfo 节点信息
type NodeInfo struct {
	ClusterKey string `json:"clusterKey"` // 集群cluster key
	Ip         string `json:"ip"`         // 节点ip
	HostName   string `json:"hostName"`   // 节点hostname
}

type RegInfo struct {
	RegID    int64  `json:"regID"`
	Url      string `json:"url"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}
