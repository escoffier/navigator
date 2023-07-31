package container

import "time"

type Container struct {
	ID        string `json:"Id"`
	Namespace string // containerd下有值
	Names     []string
	Image     string
	ImageID   string
	Command   string
	Created   int64
	Labels    map[string]string
	Status    string // running,paused
	// Ports      []Port
	// NetworkMode string `json:",omitempty"`
	// NetworkSettings *SummaryNetworkSettings
	// Mounts          []MountPoint
}

type ContainerInspect struct {
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Status       int32
	ContainerID  string
	NetworkMode  string
	IP           string
	IPV6         string
	Gateway      string
	Mac          string
	Name         string
	Namespace    string
	ClusterKey   string
	ImageName    string
	ImageID      string
	ImageDigest  string
	ImageSize    int64
	ImageCreated string
	Cmd          []string
	Arguments    []string
	Environment  []string
	// VolumeMounts   VolumeMountSlice
	Path           string
	ReservedCPU    int64
	ReservedMemory int64
	Pid            int
	K8sManaged     bool
	ProcessNumber  int
	// Processes      ProcessSlice
	// Ports          PortSlice
	User string
}

type Port struct {

	// Host IP address that the container's port is mapped to
	IP string `json:"IP,omitempty"`

	// Port on the container
	// Required: true
	PrivatePort uint16 `json:"PrivatePort"`

	// Port exposed on the host
	PublicPort uint16 `json:"PublicPort,omitempty"`

	// type
	// Required: true
	Type string `json:"Type"`
}

// SummaryNetworkSettings provides a summary of container's networks
// in /containers/json
type SummaryNetworkSettings struct {
	Networks map[string]*EndpointSettings
}

// EndpointSettings stores the network endpoint details
type EndpointSettings struct {
	// Configurations
	IPAMConfig *EndpointIPAMConfig
	Links      []string
	Aliases    []string
	// Operational data
	NetworkID           string
	EndpointID          string
	Gateway             string
	IPAddress           string
	IPPrefixLen         int
	IPv6Gateway         string
	GlobalIPv6Address   string
	GlobalIPv6PrefixLen int
	MacAddress          string
	DriverOpts          map[string]string
}

// EndpointIPAMConfig represents IPAM configurations for the endpoint
type EndpointIPAMConfig struct {
	IPv4Address  string   `json:",omitempty"`
	IPv6Address  string   `json:",omitempty"`
	LinkLocalIPs []string `json:",omitempty"`
}

// MountPoint represents a mount point configuration inside the container.
// This is used for reporting the mountpoints in use by a container.
type MountPoint struct {
	Type        Type   `json:",omitempty"`
	Name        string `json:",omitempty"`
	Source      string
	Destination string
	Driver      string `json:",omitempty"`
	Mode        string
	RW          bool
	Propagation Propagation
}

// Type represents the type of a mount.
type Type string

// Type constants
const (
	// TypeBind is the type for mounting host dir
	TypeBind Type = "bind"
	// TypeVolume is the type for remote storage volumes
	TypeVolume Type = "volume"
	// TypeTmpfs is the type for mounting tmpfs
	TypeTmpfs Type = "tmpfs"
	// TypeNamedPipe is the type for mounting Windows named pipes
	TypeNamedPipe Type = "npipe"
)

// Propagation represents the propagation of a mount.
type Propagation string

type RuntimeType string
type RuntimeInfo struct {
	RootDir      string // 根目录
	Driver       string
	DriverStatus [][2]string
	RuntimeType  string // docker/containerd/crio....
}

// ImageSummary image summary
// swagger:model ImageSummary
type ImageSummary struct {
	Namespace string
	// created
	// Required: true
	Created int64 `json:"Created"`

	// Id
	// Required: true
	ID string `json:"Id"`

	// labels
	// Required: true
	Labels map[string]string `json:"Labels"`

	// repo digests
	// Required: true
	RepoDigests []string `json:"RepoDigests"`

	// repo tags
	// Required: true
	RepoTags []string `json:"RepoTags"`

	// shared size
	// Required: true
	// SharedSize int64 `json:"SharedSize"`

	// size
	// Required: true
	// Size int64 `json:"Size"`

	// virtual size
	// Required: true
	// VirtualSize int64 `json:"VirtualSize"`
}

// ImageInspect contains response of Engine API:
// GET "/images/{name:.*}/json"
type ImageInspect struct {
	Namespace   string
	ID          string `json:"Id"`
	RepoTags    []string
	RepoDigests []string
	Parent      string
	Comment     string
	Created     string
	Author      string

	Env  []string
	Cmd  []string
	User string

	Architecture string
	Variant      string `json:",omitempty"`
	Os           string
	OsVersion    string `json:",omitempty"`
	Size         int64
	VirtualSize  int64
	GraphDriver  GraphDriverData
	RootFS       RootFS
}

// GraphDriverData Information about a container's graph driver.
// swagger:model GraphDriverData
type GraphDriverData struct {

	// data
	// Required: true
	Data map[string]string `json:"Data"`

	// name
	// Required: true
	Name string `json:"Name"`
}

// RootFS returns Image's RootFS description including the layer IDs.
type RootFS struct {
	Type      string
	Layers    []string `json:",omitempty"`
	BaseLayer string   `json:",omitempty"`
}

// HistoryResponseItem individual image layer information in response to ImageHistory operation
// swagger:model HistoryResponseItem
type HistoryResponseItem struct {

	// comment
	// Required: true
	Comment string `json:"Comment"`

	// created
	// Required: true
	Created int64 `json:"Created"`

	// created by
	// Required: true
	CreatedBy string `json:"CreatedBy"`

	// Id
	// Required: true
	ID string `json:"Id"`

	// size
	// Required: true
	Size int64 `json:"Size"`

	// tags
	// Required: true
	Tags []string `json:"Tags"`
}
