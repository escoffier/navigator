package rtdetect

import (
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/pb"
)

const (
	emptyVal        = "<NA>"
	KeyClusterKey   = "_cluster_key"
	KeyUuid         = "_uuid"
	KeyOwnerResName = "_owner_resource_name"
	KeyOwnerResKind = "_owner_resource_kind"
)

var filteredOutFields = map[string]struct{}{
	model.FieldK8sNsName:  {},
	model.FieldK8sPodName: {},
	model.FieldPodUID:     {},
	model.FieldEvtTime:    {},
}
var eventKVsMap = map[string]map[string]pb.KV{
	// event
	model.FieldEvtType: {
		"zh": {Key: "事件类型"},
		"en": {Key: "Event Type"},
	},
	model.FieldEvtTime: {
		"en": {Key: "Event Time"},
		"zh": {Key: "事件时间"},
	},
	model.FieldEvtCategory: {
		"en": {Key: "Event Category"},
		"zh": {Key: "事件分类"},
	},
	model.FieldSyscallType: {
		"en": {Key: "syscall"},
		"zh": {Key: "系统调用"},
	},
	model.FieldEvtArgName: {
		"en": {Key: "Event Arguments Name"},
		"zh": {Key: "事件参数名称"},
	},
	model.FieldEvtArgOldPath: {
		"en": {Key: "Event Argument OldPath"},
		"zh": {Key: "事件旧参数路径"},
	},
	model.FieldEvtArgPath: {
		"en": {Key: "Event Argument Path"},
		"zh": {Key: "事件参数路径"},
	},

	// Process
	model.FieldProcessPid: {
		"zh": {Key: "进程号"},
		"en": {Key: "pid"},
	},
	model.FieldProcessName: {
		"zh": {Key: "进程名"},
		"en": {Key: "procName"},
	},
	model.FieldParentProcessPid: {
		"en": {Key: "ppid"},
		"zh": {Key: "父进程号"},
	},
	model.FieldParentProcessName: {
		"zh": {Key: "父进程名称"},
		"en": {Key: "procPname"},
	},
	model.FieldPorcCmd: {
		"en": {Key: "command"},
		"zh": {Key: "进程命令行"},
	},
	model.FieldPorcLoginShellID: {
		"en": {Key: "Process LoginShell Pid"},
		"zh": {Key: "进程祖先shell进程ID"},
	},
	model.FieldProcFDC: {
		"en": {Key: "Process FD Count"},
		"zh": {Key: "进程文件描述符数量"},
	},
	model.FieldProcTerm: {
		"en": {Key: "Process Controlling Terminal"},
		"zh": {Key: "进程控制台"},
	},
	// user
	model.FieldUserName: {
		"en": {Key: "user"},
		"zh": {Key: "用户名"},
	},
	model.FieldUserLoginUID: {
		"en": {Key: "aduit user id(auid)"},
		"zh": {Key: "auid"},
	},

	// container
	model.FieldImageRepo: {
		"en": {Key: "Container Image"},
		"zh": {Key: "容器镜像"},
	},
	model.FieldImageTag: {
		"en": {Key: "Container Image Tag"},
		"zh": {Key: "容器镜像Tag"},
	},
	model.FieldContainerName: {
		"en": {Key: "Container Name"},
		"zh": {Key: "容器名称"},
	},
	model.FieldContainerID: {
		"en": {Key: "containerId"},
		"zh": {Key: "容器ID"},
	},
	model.FieldContainerType: {
		"en": {Key: "Container Type"},
		"zh": {Key: "容器类型"},
	},
	model.FieldContainerPriv: {
		"en": {Key: "Container Privileged"},
		"zh": {Key: "是否是特权容器"},
	},
	model.FieldImageDigest: {
		"en": {Key: "Container Image Digest"},
		"zh": {Key: "容器镜像Digest"},
	},
	// fd
	model.FieldFDName: {
		"en": {Key: "FD Name"},
		"zh": {Key: "文件描述符名称"},
	},
	model.FieldFDType: {
		"en": {Key: "FD Type"},
		"zh": {Key: "文件描述符类型"},
	},
	// k8s
	model.FieldK8sNsName: {
		"en": {Key: "Namespace"},
		"zh": {Key: "命名空间"},
	},
	model.FieldK8sPodName: {
		"en": {Key: "Pod Name"},
		"zh": {Key: "Pod名称"},
	},
	model.FieldPodUID: {
		"en": {Key: "PodUid"},
		"zh": {Key: "PodUid"},
	},
}

type GetOwnerResourceFunc func(namespace, podName string) (kind, name string, ok bool)

// ComparePriority
// true: p <= t
// false: p > t || p 或 t 无效
func ComparePriority(p, t string) bool {
	priorities := map[string]int{
		"EMERGENCY": 0,
		"ALERT":     1,
		"CRITICAL":  2,
		"ERROR":     3,
		"WARNING":   4,
		"NOTICE":    5,
		"INFO":      6,
		"DEBUG":     7,
	}
	pi, okp := priorities[p]
	ti, okt := priorities[t]
	if !okp || !okt {
		return false
	}
	return pi <= ti
}
