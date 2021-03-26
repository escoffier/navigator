package assets

import (
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type OnlineVulnListItem struct {
	Namespace         string                    `json:"namespace"`
	ResourceKind      string                    `json:"resourceKind"`
	ResourceName      string                    `json:"resourceName"`
	ServiceName       string                    `json:"serviceName"`
	NodeType          string                    `json:"nodeType"`
	TopVulns          []model.VulnerabilityInfo `json:"topVulnerabilities"`
	OverallSeverity   string                    `json:"overallSeverity"`
	RunningContainers []string                  `json:"runningContainers"`
	RunningPods       []string                  `json:"runningPods"`
	// internal counters
	RunningContainersSet map[string]bool                    `json:"-"`
	RunningPodsSet       map[string]bool                    `json:"-"`
	VulnerabilitiesSet   map[string]model.VulnerabilityInfo `json:"-"`
}

type OnlineVulnDetailsContainerInstance struct {
	PodName         string `json:"podName"`
	Node            string `json:"node"`
	SeccompProfile  string `json:"seccompProfile"`
	DriftPrevention string `json:"driftPrevention"`
}

type OnlineVulnDetailsContainer struct {
	Name                string                                `json:"containerName"`
	Digest              string                                `json:"digest"`
	Repository          string                                `json:"repository"`
	Tag                 string                                `json:"tag"`
	InstancesRunning    *[]OnlineVulnDetailsContainerInstance `json:"instancesRunning"`
	InstancesWaiting    *[]OnlineVulnDetailsContainerInstance `json:"instancesWaiting"`
	InstancesTerminated *[]OnlineVulnDetailsContainerInstance `json:"instancesTerminated"`
	Vulnerabilities     []model.VulnerabilityInfo             `json:"vulnerabilities"`
	SensitiveFiles      []model.Sensitive                     `json:"sensitiveFiles"`
	WasScanned          bool                                  `json:"wasScanned"`
	HarborURL           string                                `json:"harborURL"`
	TaskID              primitive.ObjectID                    `json:"taskID"`
}

type OnlineVulnDetails struct {
	Namespace    string                                `json:"namespace"`
	ResourceKind string                                `json:"resourceKind"`
	ResourceName string                                `json:"resourceName"`
	Containers   map[string]OnlineVulnDetailsContainer `json:"containers"`
}
