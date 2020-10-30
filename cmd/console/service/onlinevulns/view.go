package onlinevulns

import "gitlab.com/piccolo_su/vegeta/pkg/redclair"

type onlineVulnListItem struct {
	Namespace         string                       `json:"namespace"`
	ResourceKind      string                       `json:"resourceKind"`
	ResourceName      string                       `json:"resourceName"`
	TopVulns          []redclair.VulnerabilityInfo `json:"topVulnerabilities"`
	OverallSeverity   string                       `json:"overallSeverity"`
	RunningContainers []string                     `json:"runningContainers"`
	RunningPods       []string                     `json:"runningPods"`
	// internal counters
	RunningContainersSet map[string]bool                       `json:"-"`
	RunningPodsSet       map[string]bool                       `json:"-"`
	VulnerabilitiesSet   map[string]redclair.VulnerabilityInfo `json:"-"`
}

type onlineVulnDetailsContainerInstance struct {
	PodName string `json:"podName"`
	Node    string `json:"node"`
}

type onlineVulnDetailsContainer struct {
	Name                string                                `json:"containerName"`
	Digest              string                                `json:"digest"`
	Repository          string                                `json:"repository"`
	Tag                 string                                `json:"tag"`
	InstancesRunning    *[]onlineVulnDetailsContainerInstance `json:"instancesRunning"`
	InstancesWaiting    *[]onlineVulnDetailsContainerInstance `json:"instancesWaiting"`
	InstancesTerminated *[]onlineVulnDetailsContainerInstance `json:"instancesTerminated"`
	Vulnerabilities     []redclair.VulnerabilityInfo          `json:"vulnerabilities"`
	SensitiveFiles      []redclair.Sensitive                  `json:"sensitiveFiles"`
	WasScanned          bool                                  `json:"wasScanned"`
	HarborURL           string                                `json:"harborURL"`
}

type onlineVulnDetails struct {
	ResourceKind string                                `json:"resourceKind"`
	ResourceName string                                `json:"resourceName"`
	Namespace    string                                `json:"namespace"`
	Containers   map[string]onlineVulnDetailsContainer `json:"containers"`
}
