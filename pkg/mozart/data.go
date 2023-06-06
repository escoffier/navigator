package mozart

import (
	"sync"
	"time"
)

const (
	marcoPrefix = "MARCO::"
)

type Event struct {
	Name    string                 `json:"name"` // 唯一标识
	Payload map[string]interface{} `json:"payload"`
	Time    time.Time              `json:"time"`
}

type SignalPayload struct {
	Version1 uint16   `json:"version1"`
	Priority int32    `json:"priority"`
	Rule     string   `json:"rule"`
	Source   string   `json:"source"`
	Tags     []string `json:"tags"`
	Time     struct {
		Nanos   int32 `json:"nanos"`
		Seconds int64 `json:"seconds"`
	} `json:"time"`
	Hostname     string            `json:"hostname"`
	ClusterKey   string            `json:"cluster_key"`
	NodeName     string            `json:"node_name"`
	Output       string            `json:"output"`
	OutputFields map[string]string `json:"output_fields"`
	OutputMap    map[string]string `json:"output_map"`
}

type OutputFields struct {
	ContainerID string `json:"container_id"`
	EvtArgExe   string `json:"evt_arg_exe"`
	EvtTime     string `json:"evt_time"`
	K8sNsName   string `json:"k8s_ns_name"`
	K8sPodID    string `json:"k8s_pod_id"`
	K8sPodName  string `json:"k8s_pod_name"`
	ProcCmdLine string `json:"proc_cmdline"`
	ProcName    string `json:"proc_name"`
	ProcPID     string `json:"proc_pid"`
	ProcPName   string `json:"proc_pname"`
	ProcPPID    string `json:"proc_ppid"`
	SyscallType string `json:"syscall_type"`
	FdName      string `json:"fd_name"`
	ProcPgid    string `json:"proc_pgid"`
}

type cacheStruct struct {
	Lock     sync.Mutex
	Data     map[string][]map[string]interface{}
	Sessions map[string]map[string]interface{}
}

var cache cacheStruct
