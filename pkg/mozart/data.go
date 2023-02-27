package mozart

import (
	"fmt"
	"strings"
	"sync"
	"time"
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
	OutputFields OutputFields      `json:"output_fields"`
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

type ConfigMozartStepParamsCheckExpression string
type ConfigMozartStepParamsCheckValue []interface{}
type ConfigMozartStepParamsCheckRelatedExists []interface{}
type ConfigMozartStepParamsCheckRelatedNotExists []interface{}
type ConfigMozartStepParamsCheckRuleRecentCount []interface{}

type ConfigMozartStepParamsExecExpression string
type ConfigMozartStepParamsExecGenerateSignal map[string]interface{}
type ConfigMozartStepParamsExecSendPalace string

func (cp ConfigMozartStepParamsCheckExpression) RCode() string {
	return string(cp)
}

func (cp ConfigMozartStepParamsCheckValue) RCode() string {
	return fmt.Sprintf("CacheContext(\"%s\", input.session_id) == \"%s\"", cp[0], cp[1])
}

func (cp ConfigMozartStepParamsCheckRelatedExists) RCode() string {
	return fmt.Sprintf("ExistsInPeriod(\"%s\", \"%s\", CacheContext(\"event_time\", input.session_id), CacheContext(\"%s\", input.session_id), \"%s\")", cp[0], cp[1], cp[2], cp[3])
}

func (cp ConfigMozartStepParamsCheckRelatedNotExists) RCode() string {
	return fmt.Sprintf("NotExistsInPeriod(\"%s\", \"%s\", CacheContext(\"event_time\", input.session_id))", cp[0], cp[1])
}

func (cp ConfigMozartStepParamsCheckRuleRecentCount) RCode() string {
	return fmt.Sprintf(`RuleRecentCount("%s", "%s", CacheContext("trigger", input.session_id), CacheContext("event_time", input.session_id), %d, "%s", "%s", "%s")`,
		cp[0], cp[1], cp[2],
		strings.ReplaceAll(cp[3].(string), `"`, `\"`),
		strings.ReplaceAll(cp[4].(string), `"`, `\"`),
		cp[5])
}

func (cp ConfigMozartStepParamsExecExpression) RCode() string {
	return string(cp)
}

func (cp ConfigMozartStepParamsExecGenerateSignal) RCode() string {
	s := ""
	valueTemplate := "\"%s\":\"%s\""
	varTemplate := "\"%s\":%s"
	for k, v := range cp {
		template := valueTemplate
		if s != "" {
			s += ","
		}
		sv, sok := v.(string)
		if sok && strings.HasPrefix(sv, "input.") {
			template = varTemplate
			// todo: 处理从trigger中取值的情况
			//v = strings.ReplaceAll(sv, "input.", "CacheContext(\"") + "\")"
		}
		s += fmt.Sprintf(template, k, v)
	}
	return fmt.Sprintf("signal := generateAlertSignal(CacheContext(\"trigger.payload\", input.session_id), {%s})", s)
}

func (cp ConfigMozartStepParamsExecSendPalace) RCode() string {
	return "sendSignalToPalace(CacheContext(\"signal\", input.session_id))"
}

type ConfigMozartStepParams interface {
	RCode() string
}

type CacheStruct struct {
	Lock     sync.Mutex
	Data     map[string][]map[string]interface{}
	Sessions map[string]map[string]interface{}
}

var Cache CacheStruct

func ConvertDotKeyToUnderScore(m map[string]interface{}) map[string]interface{} {
	nm := make(map[string]interface{}, len(m))
	for k, v := range m {
		nk := strings.ReplaceAll(k, ".", "_")
		if mv, ok := v.(map[string]interface{}); ok {
			v = ConvertDotKeyToUnderScore(mv)
		}
		nm[nk] = v
	}
	return nm
}

func convertSpaceToUnderScore(s string) string {
	return strings.ReplaceAll(s, " ", "_")
}
