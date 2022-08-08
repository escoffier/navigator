package rtdetect

import (
	"context"
	"fmt"
	"strings"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
)

var (
	filteredOutRulesSet = map[string]struct{}{
		"Falco internal: syscall event drop": {},
	}

	filteredOutFields = []string{
		model.FieldK8sNsName,
		model.FieldK8sPodName,
		model.FieldPodUID,
		model.FieldEvtTime,
	}
)

type EventsOutputHandler struct {
	myNodeName string

	cm            *k8s.ClusterInfoManager
	containerInfo nodeinfo.ContainerInfoManager
	podResInfo    *nodeinfo.PodResInfo
	palaceHandler *palace.Palace
}

func NewEventsOutputHandler(myNodeName string, cm *k8s.ClusterInfoManager, containerInfo nodeinfo.ContainerInfoManager, podResInfo *nodeinfo.PodResInfo, palaceHandler *palace.Palace) *EventsOutputHandler {
	return &EventsOutputHandler{
		myNodeName:    myNodeName,
		cm:            cm,
		containerInfo: containerInfo,
		podResInfo:    podResInfo,
		palaceHandler: palaceHandler,
	}
}

func (ec *EventsOutputHandler) getOwnerInfo(podName, namespace string) (*nodeinfo.Resource, string, bool) {
	// podName, exist := data.OutputFields[model.FieldK8sPodName]
	// if !exist {
	// 	return nil, "", false
	// }
	// namespace, exist := data.OutputFields[model.FieldK8sNsName]
	// if !exist {
	// 	return nil, "", false
	// }

	res, exist := ec.podResInfo.GetPod(namespace, podName)
	if exist && res != nil {
		return res, namespace, true
	}
	return nil, "", false
}
func (ec *EventsOutputHandler) Handle(ctx context.Context, events []eventItem) error {
	for _, e := range events {
		if isEventItemWhitelisted(e.data, ec.containerInfo) {
			logging.Get().Info().Msgf("Filter out container creation post events. data: %v.", e.data)
			continue
		}

		logging.Get().Debug().Interface("data", e.data).Msg("ATT&CK handle")
		ruleCategory := "ATT&CK"
		for _, tag := range e.data.Tags {
			if tag == "Watson" || tag == "ATT&CK" {
				ruleCategory = tag
				break
			}
		}

		ruleKey := palace.RuleKey{
			Category: ruleCategory,
			Name:     e.data.Rule,
		}

		clusterName, ok := ec.cm.ClusterName()
		if !ok {
			clusterName = e.clusterKey
		}

		signalContext, podUID, podName, namespace := generateSignalContext(e.data)
		containerID, _ := signalContext[model.FieldContainerID].(string)
		containerName, _ := signalContext[model.FieldContainerName].(string)
		if containerName == "" {
			var err error
			containerName, err = model.GetInfoFromOutput("container_name=", e.data.Output)
			if err != nil || containerName == "<NA>" {
				containerName = containerID
			}
		}

		// 所有告警均存在 cluster + hostname
		scopes := []palace.Scope{
			{
				Kind: palace.ScopeKindCluster,
				ID:   e.clusterKey,
				Name: clusterName, // cluster name
			},
			{
				Kind: palace.ScopeKindHostname,
				Name: myNodeName,
			},
		}

		if namespace != "" {
			scopes = append(scopes, palace.Scope{
				Kind: palace.ScopeKindNamespace,
				Name: namespace,
			})
		}

		ownerRes, _, exist := ec.getOwnerInfo(podName, namespace)
		if exist {
			scopes = append(scopes, palace.Scope{
				Kind: palace.ScopeKindResource,
				Name: fmt.Sprintf("%s(%s)", ownerRes.Name, ownerRes.Kind),
			})
		}

		if podName != "" {
			scopes = append(scopes, palace.Scope{
				Kind: palace.ScopeKindPod,
				ID:   podUID,
				Name: podName,
			})
		}

		// 明确不是主机告警，追加 container
		if containerID != "host" {
			scopes = append(scopes, palace.Scope{
				Kind: palace.ScopeKindContainer,
				ID:   containerID,   // container id
				Name: containerName, // container name
			})
		}

		err := ec.palaceHandler.SendSignal(ruleKey, scopes, signalContext)
		if err != nil {
			logging.Get().Err(err).Str("args", fmt.Sprintf("%+v", e.data)).Msg("ATT&CK send signal to palace fails!")
		}

	}

	return nil
}
func (ec *EventsOutputHandler) CheckTarget(ctx context.Context, event eventItem) bool {
	_, exist := filteredOutRulesSet[event.data.Rule]
	return !exist
}

func generateSignalContext(data *outputs.Response) (signalContext map[string]interface{}, podUID, podName, namespace string) {
	signalContext = map[string]interface{}{}

	ppid, err := model.GetInfoFromOutput("proc_ppid=", data.Output)
	if err != nil {
		ppid = ""
	}
	procPname, err := model.GetInfoFromOutput("proc_pname=", data.Output)
	if err == nil {
		if len(ppid) > 0 {
			signalContext[model.FieldParentProcessName] = procPname + fmt.Sprintf("(%s)", ppid)
			delete(data.OutputFields, model.FieldParentProcessName)
		}
	}

	command, err := model.GetInfoFromOutput("proc_cmdline=", data.Output)
	if err != nil {
		command = ""
	}
	pid, err := model.GetInfoFromOutput("proc_pid=", data.Output)
	if err != nil {
		pid = ""
	}
	if command != "" && pid != "" {
		signalContext[model.FieldProcessName] = strings.Split(command, " ")[0] + fmt.Sprintf("(%s)", pid)
		delete(data.OutputFields, model.FieldProcessName)
	}

	if podName = data.OutputFields[model.FieldK8sPodName]; podName == "<NA>" {
		podName = ""
	}
	if namespace = data.OutputFields[model.FieldK8sNsName]; namespace == "<NA>" {
		namespace = ""
	}
	podUID = data.OutputFields[model.FieldPodUID]

	for key, value := range data.OutputFields {
		if value == "<NA>" {
			value = ""
		}

		if util.ContainsString(filteredOutFields, key) {
			continue
		}

		signalContext[key] = value

		if value == "" {
			switch key {
			case model.FieldProcessPid:
				if pid != "" {
					signalContext[model.FieldProcessPid] = pid
				}
			case model.FieldParentProcessPid:
				if ppid != "" {
					signalContext[model.FieldParentProcessPid] = ppid
				}
			case model.FieldCmdline:
				if len(command) > 0 {
					signalContext[model.FieldCmdline] = command
				}
			case "user":
				user, _ := model.GetInfoFromOutput("user=", data.Output)
				if len(user) > 0 {
					signalContext["user"] = user
				}
			case model.FieldSyscallType:
				if syscall, _ := model.GetInfoFromOutput("syscall_name=", data.Output); len(syscall) > 0 {
					signalContext[model.FieldSyscallType] = syscall
				}
			}
		}
	}

	// if data.Hostname != "" {
	// 	signalContext["nodeName"] = data.Hostname
	// }

	return signalContext, podUID, podName, namespace
}
