package assets

import (
	"bytes"
	"fmt"
	"hash/fnv"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	typeIngress  = "ingress"
	typeEgress   = "egress"
	valueUnknown = "unknown"
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
	//ScannerApiUrl     string                    `json:"-"`
	// internal counters
	RunningContainersSet map[string]bool                    `json:"-"`
	RunningPodsSet       map[string]bool                    `json:"-"`
	VulnerabilitiesSet   map[string]model.VulnerabilityInfo `json:"-"`
	Images               map[string]string                  `json:"-"`
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

type ArgumentDetails struct {
	ClusterKey    string
	Namespace     string
	ResourceName  string
	ResourceKind  string
	ContainerName string
	ProcessName   string
	Route         string
}

type ProcessInfo struct {
	ProcessName   string `json:"process_name,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	ResourceName  string `json:"resource_name"`
	ResourceKind  string `json:"resource_kind"`
	Namespace     string `json:"namespace"`
	DstPort       uint16 `json:"dst_port,omitempty"`
}

func (t *ProcessInfo) CreateUUID() uint32 {
	bui := bytes.NewBufferString(t.Namespace)
	bui.WriteByte(',')
	bui.WriteString(t.ResourceName)
	bui.WriteByte(',')
	bui.WriteString(t.ResourceKind)
	bui.WriteByte(',')
	bui.WriteString(t.ContainerName)
	bui.WriteByte(',')
	bui.WriteString(t.ProcessName)
	bui.WriteByte(',')
	bui.WriteString(fmt.Sprintf("%v", t.DstPort))

	h := fnv.New32a()
	h.Write(bui.Bytes())
	return h.Sum32()
}
