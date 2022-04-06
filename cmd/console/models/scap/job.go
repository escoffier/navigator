package scap

import "gitlab.com/piccolo_su/vegeta/cmd/console/models"

type Job struct {
	// 集群信息
	ClusterInfos []ClusterInfo `json:"clusterInfos"`
	// 策略id, 0为默认策略
	PolicyID uint `json:"policyId"`
}

// ClusterInfo 创建job的集群信息
type ClusterInfo struct {
	// 集群的id
	ClusterKey string `json:"clusterKey"`
	// 是否包含全部节点，true是包含全部节点，false为不包含全部节点
	IsAllNodes bool `json:"isAllNodes"`
	// 当不包含全部节点时的节点id列表
	Nodes []uint `json:"nodes"`
}

// ClusterInfoDetail 集群信息详情
type ClusterInfoDetail struct {
	ClusterInfo `json:",inline"`
	NodeNames   []string `json:"nodeName"`
	ClusterName string   `json:"clusterName"`
}

type JobReq struct {
	Job `json:",inline"`
}

type JobResp struct {
	models.ID `json:",inline"`
}

// JobDetail 任务详情
type JobDetail struct {
	PolicyName  string `json:"policyName"`
	ClusterName string `json:"clusterName"`
	Operator    string `json:"operator"`
	Status      uint8  `json:"status"`
	StartTime   int64  `json:"startTime"`
}
