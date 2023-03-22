package assets

import (
	"bytes"
	"fmt"
	"hash/fnv"
	corev1 "k8s.io/api/core/v1"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	typeIngress = "ingress"
	typeEgress  = "egress"
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
	ClusterKey   string
	Namespace    string
	ResourceName string
	ResourceKind string
	PodName      string
	ContainerId  string
	ProcessName  string
	Route        string
	Day          int
}

type ProcessInfo struct {
	ClusterID     string    `json:"cluster_id,omitempty"`
	ProcessName   string    `json:"process_name,omitempty"`
	ContainerId   string    `json:"container_id,omitempty"`
	ContainerName string    `json:"container_name,omitempty"`
	PodName       string    `json:"pod_name,omitempty"`
	ResourceName  string    `json:"resource_name"`
	ResourceKind  string    `json:"resource_kind"`
	Namespace     string    `json:"namespace"`
	CreateAt      time.Time `json:"create_at"`
	UpdateAt      time.Time `json:"update_at"`
	LinkCount     int       `json:"link_count"`
	DstPort       uint16    `json:"dst_port,omitempty"`
}

func (t *ProcessInfo) CreateUUID() uint32 {
	bui := bytes.NewBufferString(t.Namespace)
	bui.WriteByte(',')
	bui.WriteString(t.ResourceName)
	bui.WriteByte(',')
	bui.WriteString(t.ResourceKind)
	bui.WriteByte(',')
	bui.WriteString(t.ContainerId)
	bui.WriteByte(',')
	bui.WriteString(t.ProcessName)
	bui.WriteByte(',')
	bui.WriteString(fmt.Sprintf("%v", t.DstPort))

	h := fnv.New32a()
	_, _ = h.Write(bui.Bytes())
	return h.Sum32()
}

type ImageResponse struct {
	ID                int64                `json:"id"`
	Digest            string               `json:"digest"`
	Library           string               `json:"library"`
	NodeIP            string               `json:"node_ip"`
	ScanStatus        int                  `json:"scan_status"`
	CompleteTime      int64                `json:"complete_time"`
	Questions         []model.QuestionInfo `json:"questions"`
	FullRepoName      string               `json:"full_repo_name"`
	Tags              string               `json:"tags"`
	ImageType         int64                `json:"image_type"`
	RiskScore         float64              `json:"risk_score"`
	RegistryID        int64                `json:"registry_id"`
	RegistryName      string               `json:"registry_name"`
	RegistryDeletedAt int64                `json:"registry_deleted_at"`
	FromType          int64                `json:"from_type"`
	Trusted           int64                `json:"trusted"`
	HasFixedVulu      int64                `json:"has_fixed_vulu"`
	Online            bool                 `json:"online"`
	Os                string               `json:"os"`
	NodeHostname      string               `json:"node_hostname"`
	IsReinforce       int64                `json:"is_reinforce"`
	PrivilegedBoot    int64                `json:"privileged_boot"`
}
type ImageInfo struct {
	Name string `json:"name"`
	UUID uint32 `json:"uuid"`
}

type ContainerInfo struct {
	Name                string                `json:"name"`
	ID                  uint32                `gorm:"column:id;type:bigint;primaryKey" json:"id,omitempty"`
	CreatedAt           time.Time             `gorm:"column:created_at" json:"createdAt"`
	UpdatedAt           time.Time             `gorm:"column:updated_at" json:"updatedAt"`
	Status              int32                 `gorm:"column:status"`
	ContainerID         string                `gorm:"column:container_id" json:"containerID"`
	ClusterKey          string                `json:"clusterKey" gorm:"column:cluster_key;index:idx_prr_res,priority:1"`
	PodIP               string                `json:"podIP,omitempty"`
	PodUID              string                `json:"podUID" gorm:"column:pod_uid"`
	NodeIP              string                `json:"nodeIP,omitempty"`
	NodeOS              string                `json:"nodeOS"`
	Namespace           string                `json:"namespace" gorm:"column:namespace;index:idx_prr_res,priority:2"`
	PodName             string                `json:"podName"`
	Image               string                `json:"image"`
	Library             string                `json:"library"`
	ContainerInfo       *model.ContainerInfos `json:"containerInfo"`
	Environment         []corev1.EnvVar       `json:"environment"`
	Cmd                 []string              `json:"cmd"`
	Arguments           []string              `json:"arguments"`
	HostNetwork         bool                  `json:"hostNetwork"`
	Privileged          bool                  `json:"privileged"`
	ImageRiskInfo       *ImageRiskOverview    `json:"imageRiskInfo"`
	RegistryRiskInfo    *RegistryRisks        `json:"registryRiskInfo"`
	HostRiskInfo        map[string]string     `json:"hostRiskInfo"`
	IsInternetVisitable bool                  `json:"isInternetVisitable"`
	PoolName            string                `json:"poolName"`
	PoolUID             string                `json:"poolUID"`
	PoolPodUID          string                `json:"poolPodUID"`
	PoolPodName         string                `json:"poolPodName"`
	OffsetID            int64                 `json:"offsetID"`
}

type ImageRiskOverview struct {
	Uuid               uint32 `json:"uuid"`
	IsTrusted          bool   `json:"isTrusted"`
	IsSecure           bool   `json:"isSecure"`
	VulnerabilityNum   int32  `json:"vulnerabilityNum"`
	VulnerabilityLevel string `json:"vulnerabilityLevel"`
	MalwareNum         int32  `json:"malwareNum"`
	SensitiveFilesNum  int32  `json:"sensitiveFilesNum"`
	WebshellNum        int32  `json:"webshellNum"`
}

type RegistryRisks struct {
	RegistryUrl           string
	HasContentTrustEnable bool
	AuthEnable            bool
}
