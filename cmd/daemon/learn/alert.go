package learn

import (
	"fmt"
	"path/filepath"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
)

const (
	AlertCategory     = "ImmuneDefense"
	FileAlertRuleName = "File access exceptions in containers"
	CmdAlertRuleName  = "Command Execution Exception"
)

type Alert struct {
	palaceHandler *palace.Palace
}

type FileEventArg struct {
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
	FilePath      string // file path in container
	Permission    string // permission
}

type CmdEventArg struct {
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
	Cmd           string // command
	Path          string // path
	User          string // user
}

func (a *Alert) genFilePalaceSignalParams(arg *FileEventArg, category, name model.AlertKind) (palace.RuleKey, []palace.Scope, map[string]interface{}) {
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

	// event params
	params := map[string]interface{}{
		"file_name":  filepath.Base(arg.FilePath), // file name (base name)
		"file_path":  arg.FilePath,
		"permission": arg.Permission,
	}

	return ruleKey, scopes, params
}

func (a *Alert) genCmdPalaceSignalParams(arg *CmdEventArg, category, name model.AlertKind) (palace.RuleKey, []palace.Scope, map[string]interface{}) {
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

	// event params
	params := map[string]interface{}{
		"cmd":          arg.Cmd,
		"process_path": arg.Path,
		"user":         arg.User,
	}

	return ruleKey, scopes, params
}

func (a *Alert) Send(ruleKey palace.RuleKey, scopes []palace.Scope, params map[string]interface{}) error {
	// logging.GetLogger().Debug().Msgf("send signal: %v, %v, %v", ruleKey, scopes, params)
	err := a.palaceHandler.SendSignal(ruleKey, scopes, params)
	if err != nil {
		logging.GetLogger().Err(err).Msg("send signal failed")
	}
	return err
}

func NewAlert() (*Alert, error) {
	a := &Alert{}
	palaceHandler, err := palace.Init()
	if err != nil {
		return nil, err
	}
	a.palaceHandler = &palaceHandler
	return a, nil
}
