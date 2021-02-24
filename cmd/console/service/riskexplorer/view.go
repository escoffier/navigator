package riskexplorer

import (
	"encoding/json"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type NamespaceSummary struct {
	Name         string            `json:"namespaceName"`
	ServicesList []*ServiceSummary `json:"serviceList"`
}

type ServiceSummary struct {
	ContainersList []*ContainerSummary `json:"containerList"`
	FinalSeverity  string              `json:"finalSeverity"`
	RiskLevel      int                 `json:"riskLevel"`
	ServiceName    string              `json:"serviceName"`
	Namespace      string              `json:"namespace"`
	RiskTypes      map[RiskType]int    `json:"tag"`
}

type ContainerSummary struct {
	ContainerID   string           `json:"containerID"`
	Name          string           `json:"name"`
	Namespace     string           `json:"namespaceName"`
	ServiceName   string           `json:"serviceName"`
	FinalSeverity string           `json:"finalSeverity,omitempty"`
	RiskTypes     map[RiskType]int `json:"tag,omitempty"`
}

type ServiceDetail struct {
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
