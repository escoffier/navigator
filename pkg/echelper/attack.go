package echelper

import (
	"fmt"
	"strings"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
)

var eventKVsMap = map[string]map[string]pb.KV{
	// event
	"evt.type": {
		"zh": {Key: "事件类型"},
		"en": {Key: "Event Type"},
	},
	"evt.time": {
		"en": {Key: "Event Time"},
		"zh": {Key: "事件时间"},
	},
	"evt.category": {
		"en": {Key: "Event Category"},
		"zh": {Key: "事件分类"},
	},
	"syscall.type": {
		"en": {Key: "syscall"},
		"zh": {Key: "系统调用"},
	},
	"evt.arg.name": {
		"en": {Key: "Event Arguments Name"},
		"zh": {Key: "事件参数名称"},
	},
	"evt.arg.oldpath": {
		"en": {Key: "Event Argument OldPath"},
		"zh": {Key: "事件旧参数路径"},
	},
	"evt.arg.path": {
		"en": {Key: "Event Argument Path"},
		"zh": {Key: "事件参数路径"},
	},

	// Process
	"proc.pid": {
		"zh": {Key: "进程号"},
		"en": {Key: "pid"},
	},
	"proc.name": {
		"zh": {Key: "进程名"},
		"en": {Key: "procName"},
	},
	"proc.ppid": {
		"en": {Key: "ppid"},
		"zh": {Key: "父进程号"},
	},
	"proc.pname": {
		"zh": {Key: "父进程名称"},
		"en": {Key: "procPname"},
	},
	"proc.cmdline": {
		"en": {Key: "command"},
		"zh": {Key: "进程命令行"},
	},
	"proc.loginshellid": {
		"en": {Key: "Process LoginShell Pid"},
		"zh": {Key: "进程祖先shell进程ID"},
	},
	"proc.fdopencount": {
		"en": {Key: "Process FD Count"},
		"zh": {Key: "进程文件描述符数量"},
	},
	// user
	"user.name": {
		"en": {Key: "user"},
		"zh": {Key: "用户名"},
	},
	"user.loginuid": {
		"en": {Key: "aduit user id(auid)"},
		"zh": {Key: "auid"},
	},

	// container
	"container.image.repository": {
		"en": {Key: "Container Image"},
		"zh": {Key: "容器镜像"},
	},
	"container.image.tag": {
		"en": {Key: "Container Image Tag"},
		"zh": {Key: "容器镜像Tag"},
	},
	"container.name": {
		"en": {Key: "Container Name"},
		"zh": {Key: "容器名称"},
	},
	"container.id": {
		"en": {Key: "containerId"},
		"zh": {Key: "容器ID"},
	},
	"container.type": {
		"en": {Key: "Container Type"},
		"zh": {Key: "容器类型"},
	},
	"container.privileged": {
		"en": {Key: "Container Privileged"},
		"zh": {Key: "是否是特权容器"},
	},
	"container.image.digest": {
		"en": {Key: "Container Image Digest"},
		"zh": {Key: "容器镜像Digest"},
	},
	// fd
	"fd.name": {
		"en": {Key: "FD Name"},
		"zh": {Key: "文件描述符名称"},
	},
	"fd.type": {
		"en": {Key: "FD Type"},
		"zh": {Key: "文件描述符类型"},
	},
	// k8s
	"k8s.ns.name": {
		"en": {Key: "Namespace"},
		"zh": {Key: "命名空间"},
	},
	"k8s.pod.name": {
		"en": {Key: "Pod Name"},
		"zh": {Key: "Pod名称"},
	},
	"k8s.pod.id": {
		"en": {Key: "PodUid"},
		"zh": {Key: "PodUid"},
	},
}

func generateEventCustomKVs(data *outputs.Response) (kvs []*pb.MultiLanguageKV, podName string, namespace string) {

	kvs = make([]*pb.MultiLanguageKV, 0, len(data.OutputFields)+5)
	pid, err := model.GetInfoFromOutput("proc_pid=", data.Output)
	if err != nil {
		pid = ""
	}

	ppid, err := model.GetInfoFromOutput("proc_ppid=", data.Output)
	if err != nil {
		ppid = ""
	}

	procPname, err := model.GetInfoFromOutput("proc_name=", data.Output)
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
		switch key {
		case "proc.pid":
			pidFromFields = value
		case "proc.ppid":
			ppidFromFields = value
		case "proc.cmdline":
			commandFromFields = value
		case "user":
			userFromFields = value
		case "syscall.type":
			syscallFromFields = value
		case "k8s.pod.name":
			podName = value
		case "k8s.ns.name":
			namespace = value
		}
		if key == "proc.pname" && procPname != "" {
			continue
		} else if key == "proc.name" && procName != "" {
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
	return kvs, podName, namespace
}

func GenerateAttackEvent(uuidGenerator *uuid.Generator, data *outputs.Response, clusterKey string) *pb.SendNotificationReq {

	customKVs, podName, namespace := generateEventCustomKVs(data)
	req := &pb.SendNotificationReq{
		RuleKey: &pb.RuleKey{
			Module:   model.AlertModuleContainerSecurity,
			Category: "ATT&CK",
			Name:     data.Rule,
		},
		NotifyContext: &pb.Context{
			Cluster:   clusterKey,
			PodName:   podName,
			Namespace: namespace,
			CustomKV:  customKVs,
		},
		Timestamp: data.Time.GetSeconds(),
		UUID:      uuidGenerator.GenerateUUID(),
	}

	return req
}
