package riskexplorer

import (
	"encoding/json"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type NamespaceSummary struct {
	Name          string             `json:"namespaceName"`
	ClusterKey    string             `json:"clusterKey"`
	ResourcesList []*ResourceSummary `json:"resourcesList"`
}

type RiskTypeDesc struct {
	Key       string `json:"key"`
	Count     int    `json:"count"`
	DisplayZh string `json:"displayZh"`
	DisplayEn string `json:"displayEn"`
}
type ResourceSummary struct {
	ContainersList   []*ContainerSummary     `json:"containerList"`
	FinalSeverity    string                  `json:"finalSeverity"`
	RiskLevel        int                     `json:"riskLevel"`
	ResourceName     string                  `json:"resourceName"`
	NodeType         string                  `json:"nodeType"`
	ResourceKind     string                  `json:"resourceKind"`
	Namespace        string                  `json:"namespace"`
	RiskTypes        map[string]RiskTypeDesc `json:"tag"`
	Alias            string                  `json:"alias"`
	Managers         []string                `json:"managers"`
	Authority        string                  `json:"authority"`
	AppType          string                  `json:"appType"`
	AppTargetName    string                  `json:"appTargetName"`
	AppTargetVersion string                  `json:"appTargetVersion"`
}

type ContainerSummary struct {
	Name          string                  `json:"name"`
	Namespace     string                  `json:"namespaceName"`
	ResourceName  string                  `json:"resourceName"`
	FinalSeverity string                  `json:"finalSeverity,omitempty"`
	Image         string                  `json:"image"`
	RiskTypes     map[string]RiskTypeDesc `json:"tag,omitempty"`
}

type ResourceDetail struct {
	Containers []*ContainerDetail `json:"containers"`
	RiskItems  []*RiskTypeDetail  `json:"riskItems"`
}

type NodeInfo struct {
	Node    string `json:"node"`
	PodName string `json:"podName"`
}

type ContainerDetail struct {
	Name                string            `json:"name"`
	Digest              string            `json:"digest"`
	Repository          string            `json:"repository"`
	RepoTag             string            `json:"repoTag"`
	InstancesRunning    []NodeInfo        `json:"instancesRunning"`
	InstancesTerminated []NodeInfo        `json:"instancesTerminated"`
	InstancesWaiting    []NodeInfo        `json:"instancesWaiting"`
	RiskItems           []*RiskTypeDetail `json:"riskItems"`
}

type RiskTypeDetail struct {
	RiskType string          `json:"riskType"`
	RiskData json.RawMessage `json:"riskData"`
}

type ImageVulnsDetails struct {
	ScanTaskID      string                    `json:"scanTaskID"`
	HarborURL       string                    `json:"harborURL,omitempty"`
	SensitiveFiles  []model.Sensitive         `json:"sensitiveFiles"`
	Vulnerabilities []model.VulnerabilityInfo `json:"vulnerabilities"`
}
