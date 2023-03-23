package mozart

import (
	"fmt"
	"strings"
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

type configMozartStepParamsCheckExpression string
type configMozartStepParamsCheckValue []interface{}
type configMozartStepParamsCheckRelatedExists []interface{}
type configMozartStepParamsCheckRelatedNotExists []interface{}
type configMozartStepParamsCheckRuleRecentCount []interface{}
type configMozartStepParamsCheckRegexMatch []interface{}

type configMozartStepParamsExecExpression string
type configMozartStepParamsExecGenerateSignal map[string]interface{}
type configMozartStepParamsExecSendPalace string

func (cp configMozartStepParamsCheckExpression) rCode() string {
	return string(cp)
}

func (cp configMozartStepParamsCheckValue) rCode() string {
	return fmt.Sprintf("CacheContext(\"%s\", input.session_id) == \"%s\"", cp[0], cp[1])
}

func (cp configMozartStepParamsCheckRelatedExists) rCode() string {
	return fmt.Sprintf("ExistsInPeriod(\"%s\", \"%s\", CacheContext(\"event_time\", input.session_id), CacheContext(\"%s\", input.session_id), \"%s\")", cp[0], cp[1], cp[2], cp[3])
}

func (cp configMozartStepParamsCheckRelatedNotExists) rCode() string {
	return fmt.Sprintf("NotExistsInPeriod(\"%s\", \"%s\", CacheContext(\"event_time\", input.session_id))", cp[0], cp[1])
}

func (cp configMozartStepParamsCheckRuleRecentCount) rCode() string {
	return fmt.Sprintf(`RuleRecentCount("%s", "%s", CacheContext("trigger", input.session_id), CacheContext("event_time", input.session_id), %d, "%s", "%s", "%s")`,
		cp[0], cp[1], cp[2],
		strings.ReplaceAll(cp[3].(string), `"`, `\"`),
		strings.ReplaceAll(cp[4].(string), `"`, `\"`),
		cp[5])
}

func (cp configMozartStepParamsCheckRegexMatch) rCode() string {
	return fmt.Sprintf(`CheckRegexMatch("%s", CacheContext("%s", input.session_id))`, strings.ReplaceAll(cp[0].(string), `\`, `\\`), cp[1])
}

func (cp configMozartStepParamsExecExpression) rCode() string {
	return string(cp)
}

func (cp configMozartStepParamsExecGenerateSignal) rCode() string {
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

func (cp configMozartStepParamsExecSendPalace) rCode() string {
	return "sendSignalToPalace(CacheContext(\"signal\", input.session_id))"
}

type ConfigMozartStepParams interface {
	rCode() string
}

type cacheStruct struct {
	Lock     sync.Mutex
	Data     map[string][]map[string]interface{}
	Sessions map[string]map[string]interface{}
}

var cache cacheStruct
