package rtdetect

import (
	"fmt"
	"strings"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
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

func generateEventCustomKVs(data *outputs.Response) (kvs []*pb.MultiLanguageKV, podUID, podName, namespace string) {

	kvs = make([]*pb.MultiLanguageKV, 0, len(data.OutputFields)+5)
	pid, err := model.GetInfoFromOutput("proc_pid=", data.Output)
	if err != nil {
		pid = ""
	}

	ppid, err := model.GetInfoFromOutput("proc_ppid=", data.Output)
	if err != nil {
		ppid = ""
	}

	procPname, err := model.GetInfoFromOutput("proc_pname=", data.Output)
	if err == nil {
		if len(ppid) > 0 {
			procPname = procPname + fmt.Sprintf("(%s)", ppid)
		}
	} else {
		procPname = ""
	}
	if procPname != "" {
		kvs = append(kvs, &pb.MultiLanguageKV{
			KVHash: map[string]*pb.KV{
				"zh": {Key: "父进程名称", Value: procPname},
				"en": {Key: "procPname", Value: procPname},
			},
		})
	}

	command, err := model.GetInfoFromOutput("proc_cmdline=", data.Output)
	if err != nil {
		command = ""
	}

	procName := ""
	if command != "" {
		if pid != "" {
			procName = strings.Split(command, " ")[0] + fmt.Sprintf("(%s)", pid)
		}

	}
	if procName != "" {
		kvs = append(kvs, &pb.MultiLanguageKV{
			KVHash: map[string]*pb.KV{
				"zh": {Key: "进程名称", Value: procName},
				"en": {Key: "procName", Value: procName},
			},
		})
	}

	var pidFromFields, ppidFromFields, commandFromFields, userFromFields, syscallFromFields string
	for key, value := range data.OutputFields {
		if value == emptyVal {
			value = ""
		}
		switch key {
		case model.FieldProcessPid:
			pidFromFields = value
		case model.FieldParentProcessPid:
			ppidFromFields = value
		case model.FieldCmdline:
			commandFromFields = value
		case "user":
			userFromFields = value
		case model.FieldSyscallType:
			syscallFromFields = value
		case model.FieldK8sPodName:
			podName = value
		case model.FieldK8sNsName:
			namespace = value
		case model.FieldPodUID:
			podUID = value
		}
		if key == model.FieldParentProcessName && procPname != "" {
			continue
		} else if key == model.FieldProcessName && procName != "" {
			continue
		} else if _, toFilterOut := filteredOutFields[key]; toFilterOut {
			continue
		}

		if mkv, exist := eventKVsMap[key]; exist {
			mlkv := new(pb.MultiLanguageKV)

			mlkv.KVHash = make(map[string]*pb.KV, len(mkv))
			for language, val := range mkv {
				kv := val
				mlkv.KVHash[language] = &kv
				mlkv.KVHash[language].Value = value
			}
			kvs = append(kvs, mlkv)
		} else {
			kvs = append(kvs, &pb.MultiLanguageKV{
				KVHash: map[string]*pb.KV{
					"en": {Key: key, Value: value},
					"zh": {Key: key, Value: value},
				},
			})
		}
	}

	if syscallFromFields == "" {
		syscall, _ := model.GetInfoFromOutput("syscall_name=", data.Output)
		if len(syscall) > 0 {
			kvs = append(kvs, &pb.MultiLanguageKV{
				KVHash: map[string]*pb.KV{
					"en": {Key: "syscall", Value: syscall},
					"zh": {Key: "系统调用", Value: syscall},
				},
			})
		}

	}
	if userFromFields == "" {
		user, _ := model.GetInfoFromOutput("user=", data.Output)
		if len(user) > 0 {
			kvs = append(kvs, &pb.MultiLanguageKV{
				KVHash: map[string]*pb.KV{
					"en": {Key: "user", Value: user},
					"zh": {Key: "用户名称", Value: user},
				},
			})
		}
	}
	if commandFromFields == "" && len(command) > 0 {
		kvs = append(kvs, &pb.MultiLanguageKV{
			KVHash: map[string]*pb.KV{
				"en": {Key: "Process Commandline", Value: command},
				"zh": {Key: "进程命令行"},
			},
		})

	}

	if pidFromFields == "" && pid != "" {
		kvs = append(kvs, &pb.MultiLanguageKV{
			KVHash: map[string]*pb.KV{
				"en": {Key: "pid", Value: pid},
				"zh": {Key: "进程号", Value: pid},
			},
		})
	}

	if ppidFromFields == "" && ppid != "" {
		kvs = append(kvs, &pb.MultiLanguageKV{
			KVHash: map[string]*pb.KV{
				"en": {Key: "ppid", Value: ppid},
				"zh": {Key: "父进程号", Value: ppid},
			},
		})
	}
	if data.Hostname != "" {
		kvs = append(kvs, &pb.MultiLanguageKV{
			KVHash: map[string]*pb.KV{
				"en": {Key: "nodeName", Value: data.Hostname},
				"zh": {Key: "节点名称", Value: data.Hostname},
			},
		})
	}
	return kvs, podUID, podName, namespace
}

type GetOwnerResourceFunc func(namespace, podName string) (kind, name string, ok bool)

func GenerateAttackEvent(module, category string, data *outputs.Response, clusterKey string, uuid uint64, ownerFunc GetOwnerResourceFunc) *pb.SendNotificationReq {
	if module == "" {
		module = model.AlertModuleContainerSecurity
	}
	if category == "" {
		category = "ATT&CK"
	}
	var timestamp int64
	if data.Time == nil {
		timestamp = time.Now().Unix()
	} else {
		timestamp = data.Time.GetSeconds()
	}
	customKVs, podUID, podName, namespace := generateEventCustomKVs(data)
	req := &pb.SendNotificationReq{
		RuleKey: &pb.RuleKey{
			Module:   module,
			Category: category,
			Name:     data.Rule,
		},
		NotifyContext: &pb.Context{
			Cluster:   clusterKey,
			PodName:   podName,
			PodUID:    podUID,
			Namespace: namespace,
			CustomKV:  customKVs,
		},
		Timestamp: timestamp,
		UUID:      uuid,
	}
	if ownerFunc != nil {
		kind, name, ok := ownerFunc(namespace, podName)
		if ok && len(name) > 0 && len(kind) > 0 {
			req.NotifyContext.ServiceID = strings.Join([]string{kind, name}, "/")
		}
	}

	return req
}

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
