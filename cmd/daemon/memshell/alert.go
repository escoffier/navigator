package memshell

import (
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
	// "strings"
)

const (
	AlertCategory = "WebShell"
	AlertRuleName = "WebShell found in container"
)

type Alert struct {
	palaceHandler *palace.Palace // for send event
}

type EventArg struct {
	ClusterID     string
	Cluster       string
	ResourceKind  string
	ResourceName  string
	Hostname      string
	Namespace     string
	PodName       string
	PodUID        string
	ContainerID   string
	ContainerName string
	WebshellType  string
	Path          string
}

func (a *Alert) genPalaceSignalParams(arg *EventArg, category, name model.AlertKind) (palace.RuleKey, []palace.Scope, map[string]interface{}) {
	ruleKey := palace.RuleKey{
		Version1: 2,
		Category: string(category),
		Name:     string(name),
	}

	// kind,name must have value
	scopes := []palace.Scope{
		{
			Kind: palace.ScopeKindContainer,
			ID:   arg.ContainerID,   // container id
			Name: arg.ContainerName, // container name
		},
		{
			Kind: palace.ScopeKindPod,
			ID:   arg.PodUID,  // pod id
			Name: arg.PodName, // pod name
		},
		{
			Kind: palace.ScopeKindNamespace,
			Name: arg.Namespace, // namespace name
		},
		{
			Kind: palace.ScopeKindHostname,
			Name: arg.Hostname,
		},
		{
			Kind: palace.ScopeKindCluster,
			ID:   arg.ClusterID,
			Name: arg.Cluster, // cluster name
		},
		{
			Kind: palace.ScopeKindResource,
			Name: fmt.Sprintf("%s(%s)", arg.ResourceName, arg.ResourceKind),
		},
		{
			Kind: palace.ScopeKindScene,
			ID:   palace.ScopeIDSceneK8s,
			Name: palace.ScopeNameSceneK8s,
		},
	}

	signalContext := map[string]interface{}{
		"container.id":   arg.ContainerID,
		"container.name": arg.ContainerName,
		"nameSpace":      arg.Namespace,
		"webshell.type":  arg.WebshellType,
		"webshell.path":  arg.Path,

		// "Exist malicious file": strings.Join(arg.Malware, ","),
	}

	return ruleKey, scopes, signalContext
}

func (a *Alert) genPalaceSignalParamsForRawContainer(arg *EventArg, category, name model.AlertKind) (palace.RuleKey, []palace.Scope, map[string]interface{}) {
	ruleKey := palace.RuleKey{
		Version1: 2,
		Category: string(category),
		Name:     string(name),
	}

	// kind,name must have value
	scopes := []palace.Scope{
		{
			Kind: palace.ScopeKindContainer,
			ID:   arg.ContainerID,   // container id
			Name: arg.ContainerName, // container name
		},
		{
			Kind: palace.ScopeKindHostname,
			Name: arg.Hostname,
		},
		{
			Kind: palace.ScopeKindCluster,
			ID:   arg.ClusterID,
			Name: arg.Cluster, // cluster name
		},
		{
			Kind: palace.ScopeKindScene,
			ID:   palace.ScopeIDSceneNk8s,
			Name: palace.ScopeNameSceneNk8s,
		},
	}

	signalContext := map[string]interface{}{
		"container.id":   arg.ContainerID,
		"container.name": arg.ContainerName,
		"webshell.type":  arg.WebshellType,
		"webshell.path":  arg.Path,
	}

	return ruleKey, scopes, signalContext
}
func (a *Alert) Send(arg *EventArg) error {
	if len(arg.PodUID) == 0 {
		// for raw container
		ruleKey, scopes, signalContext := a.genPalaceSignalParamsForRawContainer(arg, AlertCategory, AlertRuleName)
		return a.palaceHandler.SendSignal(ruleKey, scopes, signalContext)
	}

	// for k8s pod
	ruleKey, scopes, signalContext := a.genPalaceSignalParams(arg, AlertCategory, AlertRuleName)
	return a.palaceHandler.SendSignal(ruleKey, scopes, signalContext)
}

func NewAlert() (*Alert, error) {
	a := &Alert{}
	palaceHandler, err := palace.Init()
	if err != nil {
		logging.Get().Err(err).Msg("failed to create event handler")
		return nil, err
	}
	a.palaceHandler = &palaceHandler
	return a, nil
}
