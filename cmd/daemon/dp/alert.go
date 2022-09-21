package dp

import (
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
	"gitlab.com/security-rd/go-pkg/pb"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
)

type Reporter struct {
	uuidGenerator *uuid.Generator
	cli           pb.EventsCenterCollectionServiceClient
}

type EventArg struct {
	ClusterID     string
	Cluster       string
	Hostname      string
	Namespace     string
	PodName       string
	PodUID        string
	ContainerID   string
	ContainerName string
	FilePath      string
	Syscall       string
	Action        string
	crc32Expected string
	crc32Actual   string
	ImageRepoTags string
	ImageDigest   string
	reason        string
}

func genPalaceSignalParams(arg *EventArg, cPodInfo containerPolicy, category, name model.AlertKind) (palace.RuleKey, []palace.Scope, map[string]interface{}) {
	ruleKey := palace.RuleKey{
		Category: string(category),
		Name:     string(name),
	}

	// 告警信号的工作负载、影响范围
	// scopes为列表格式，存在递进关系： container -> cluster
	// kind、name 为必填，id若有则需填写
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
			Name: fmt.Sprintf("%s(%s)", cPodInfo.resourceName, cPodInfo.resourceKind),
		},
		{
			Kind: palace.ScopeKindScene,
			ID:   palace.ScopeIDSceneK8s,
			Name: palace.ScopeNameSceneK8s,
		},
	}

	expectStr := ""
	if arg.crc32Expected != "" {
		expectStr = arg.crc32Expected
	} else {
		expectStr = "none"
	}
	// 告警信号的上下文
	// 内容和老版的customKV大体一致，但移除了多语言的部分
	// 只需定义context的原始key-value，可以直接使用老版的英文k-v
	signalContext := map[string]interface{}{
		"ruleCategory":   category,
		"container.id":   arg.ContainerID,
		"container.name": arg.ContainerName,
		"syscall":        arg.Syscall,
		"crc32Expected":  expectStr,
		"crc32Actual":    arg.crc32Actual,
		"action":         arg.Action,
		"filePath":       arg.FilePath,
		"cluster":        arg.Cluster,
		"nameSpace":      arg.Namespace,
		"podName":        arg.PodName,
		"imageRepoTags":  arg.ImageRepoTags,
		"reason":         arg.reason,
	}

	return ruleKey, scopes, signalContext
}
