package model

import "time"

// 收集 监控容器的 状态，和资源指标

type TensorsecContainerMonitor struct {
	TableBase                       // id: cluster_key/namespace/podName/containerName
	ClusterKey            string    `json:"clusterKey" gorm:"column:cluster_key"`
	NodeName              string    `json:"nodeName" gorm:"column:node_name"`
	Namespace             string    `json:"namespace" gorm:"column:namespace"`
	PodName               string    `json:"podName" gorm:"column:pod_name"`
	PodIsHealth           int8      `json:"PodIsHealth" gorm:"column:pod_is_health"` // for holmes 排序
	AppLabel              string    `json:"appLabel" gorm:"column:app_label"`
	ContainerName         string    `json:"containerName" gorm:"column:container_name"`
	ContainerStatus       int8      `json:"containerStatus" gorm:"column:container_status"` // ContainerState_running:0
	Version               string    `json:"version" gorm:"column:version"`
	MetricsLastTime       time.Time `json:"metricsLastTime" gorm:"column:metrics_last_time"`
	TimeGap               int64     `json:"timeGap" gorm:"column:time_gap"`            // 微秒
	CpuUsageLast          uint64    `json:"cpuUsageLast" gorm:"column:cpu_usage_last"` // 微秒
	CpuUsageCurrent       uint64    `json:"cpuUsageCurrent" gorm:"column:cpu_usage_current"`
	CpuSystemUsageLast    uint64    `json:"cpuSystemUsageLast" gorm:"column:cpu_system_usage_last"`
	CpuSystemUsageCurrent uint64    `json:"cpuSystemUsageCurrent" gorm:"column:cpu_system_usage_current"`
	OnlineCpus            uint32    `json:"OnlineCpus" gorm:"column:online_cpus"`
	CpuLimit              float32   `json:"cpuLimit" gorm:"column:cpu_limit"`
	MemLast               uint64    `json:"memLast" gorm:"column:mem_last"`
	MemCurrent            uint64    `json:"memCurrent" gorm:"column:mem_current"`
	MemLimit              uint64    `json:"memLimit" gorm:"column:mem_limit"`
	BlockILast            uint64    `json:"blockILast" gorm:"column:block_i_last"`
	BlockOLast            uint64    `json:"blockOLast" gorm:"column:block_o_last"`
	BlockICurrent         uint64    `json:"blockICurrent" gorm:"column:block_i_current"`
	BlockOCurrent         uint64    `json:"blockOCurrent" gorm:"column:block_o_current"`
}

func (c TensorsecContainerMonitor) TableName() string {
	return "ivan_system_monitor"
}
