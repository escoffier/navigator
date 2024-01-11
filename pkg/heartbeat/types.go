package heartbeat

import (
	"time"
)

type Action string

// FATAL: don't alter  exist const block!!!
const (
	ActionTypeBeat    Action = "beat"
	ActionTypeMetrics Action = "metrics"
)

type BeatMessage struct {
	Action Action
	Data   interface{}
}

// 心跳消息
type DataTypeBeat struct {
	*SelfInfo
	CreateTime time.Time
	BeatTime   time.Time
}

type DataTypeConMetricsInNode struct {
	ContainerMetricList []*ContainerMetric
}

type ContainerMetric struct {
	*SelfInfo
	*MetricsInfo
}

type MetricsInfo struct {
	CpuStats    CpuStats
	CpuLimit    float32
	MemUsage    uint64
	MemLimit    uint64
	BlockITotal uint64
	BLockOTotal uint64
	CollectTime time.Time
}

//
//type DataTypeMetric struct {
//	Metric    string            `json:"metric"`
//	Labels    map[string]string `json:"labels"`
//	Value     string            `json:"value"`
//	Timestamp int               `json:"timestamp"`
//}

type CpuStats struct {
	TotalUsage  uint64 `json:"total_usage"`
	SystemUsage uint64 `json:"system_cpu_usage,omitempty"`
	OnlineCPUs  uint32 `json:"online_cpus,omitempty"`
}
