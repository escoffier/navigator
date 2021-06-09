package model

import (
	"time"

	"gorm.io/datatypes"
)

type VulnMatedata struct {
	CVSS   CVSSVulnerabilityInfo    `json:"cvss,omitempty" bson:"cvss,omitempty"`
	CNNVDs []CNNVDVulnerabilityInfo `json:"cnnvds,omitempty" bson:"cnnvds,omitempty"`
	CNVDs  []CNVDVulnerabilityInfo  `json:"cnvds,omitempty" bson:"cnvds,omitempty"`
}

type PostModel struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt int
}

// 漏洞表
type Vuln struct {
	ID           uint `gorm:"primaryKey"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    int
	Name         string         `gorm:"index"` // 形如CVE-2021-28831
	Namespace    string         // 发行版名字：alpine，redhat等
	Description  string         // 描述
	Link         []string       `gorm:"-"` // 参考链接
	LinkJSON     datatypes.JSON `gorm:"type:jsonb"`
	Severity     string         // 威胁等级
	SeverityInt  int            `gorm:"column:severity_int"`
	Metadata     VulnMatedata   `gorm:"-"`
	MetadataJSON datatypes.JSON `gorm:"type:jsonb"` // 元数据
	PkgName      string         // 软件包来源
	PkgVersion   string         // 软件包版本
	FixedBy      string         `json:"fixedby" bson:"fixedby"` // 修复建议
	ExtraInfo    datatypes.JSON `gorm:"type:jsonb"`             //  预留，漏洞属性。如我们自己的漏洞评级
}

// 漏洞关联镜像表
type VulnImage struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt int
	VulnName  string
	ImageId   int64 `gorm:"index:idx_image_id"` // 镜像id
}

type ScanLayer struct { // 层级扫描结果
	ID           uint                `gorm:"primaryKey" json:"id"`
	CreatedAt    time.Time           `json:"created_at"`
	UpdatedAt    time.Time           `json:"updated_at"`
	DeletedAt    int                 `json:"deleted_at"`
	ImageId      int64               `gorm:"index:idx_image_id"   json:"image_id"`
	LayerDigest  string              `gorm:"index:idx_digest" json:"layer_digest"`
	VulnInfoJSON datatypes.JSON      `gorm:"type:jsonb" json:"-"` // 包含扫描结果的json
	VulnInfo     []VulnerabilityInfo `gorm:"-" json:"vuln_info"`

	PkgInfoJSON datatypes.JSON `gorm:"type:jsonb" json:"-"` // 软件包信息
	PkgInfo     interface{}    `gorm:"-" json:"pkg_info"`

	MaliciousInfoJSON datatypes.JSON `gorm:"type:jsonb" json:"-"`     // 恶意文件
	MaliciousInfo     []Malicious    `gorm:"-" json:"malicious_info"` // 恶意文件

	SensitiveFileJSON datatypes.JSON `gorm:"type:jsonb" json:"-"` // 敏感文console/service/image/image.go件
	SensitiveFile     []Sensitive    `gorm:"-" json:"sensitive_file"`

	IsBasic int `json:"is_basic"`
}

type ScanImage struct { // 镜像结果// 加上镜像结果,对应原来的scantasks表
	ID                    int64 `gorm:"primaryKey"`
	CreatedAt             time.Time
	UpdatedAt             time.Time
	DeletedAt             int
	ImageId               int64                      `gorm:"index:idx_image_id"`
	RiskScore             float64                    `gorm:"column:risk_score" json:"risk_score" bson:"risk_score"`
	VulnInfo              []VulnerabilityInfo        `gorm:"-"`
	VulnInfoJSON          datatypes.JSON             `gorm:"type:jsonb"` // 漏洞结果汇总
	PkgInfoJSON           datatypes.JSON             `gorm:"type:jsonb"` // 软件包信息
	MaliciousInfoJSON     datatypes.JSON             `gorm:"type:jsonb"` // 恶意文件
	MaliciousInfo         []Malicious                `gorm:"-"`          // 恶意文件
	SensitiveFile         []Sensitive                `gorm:"-"`
	SensitiveFileJSON     datatypes.JSON             `gorm:"type:jsonb"` // 敏感文件
	PerLayerReport        []VulnerabilityLayerReport `gorm:"-"`
	PerLayerReportJSON    datatypes.JSON             `gorm:"type:jsonb"`                                          // 层结果汇总
	OverallSeverity       string                     `json:"overallSeverity" bson:"overallSeverity"`              // 评级
	OverallSeverityInt    int                        `json:"overallSeverityInt" bson:"overallSeverityInt"`        // 评级int
	SeverityHistogram     SeverityHistogramInfo      `gorm:"-" json:"severityHistogram" bson:"severityHistogram"` // 评级集合
	SeverityHistogramJSON datatypes.JSON             `gorm:"type:jsonb"`
	ScanTaskId            string
	Status                string // 扫描状态
	Message               string // 错误信息
	StartedAt             int64  // 扫描开始时间
	FinishAt              int64  // 扫描结束时间
}

func (i ScanImage) TableName() string {
	return "scan_images"
}

// 镜像信息表
type ImageList struct {
	ID             int64     `gorm:"primary_key;AUTO_INCREMENT" json:"id" `
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Url            string
	FullRepoName   string                 `gorm:"column:full_repo_name"  json:"full_repo_name"`
	Tags           string                 `gorm:"column:tags" json:"tags" bson:"tags"`
	Digest         string                 `gorm:"index:idx:digest_library,priority:1" json:"digest" bson:"digest"`
	OS             string                 `gorm:"column:os" json:"os" bson:"os"`
	Size           int                    `gorm:"column:size" json:"size" bson:"size"`
	Library        string                 `gorm:"index:idx:digest_library,priority:2" json:"library" bson:"library"`
	Questions      []QuestionInfo         `gorm:"-" json:"questions" bson:"questions"`
	CompleteTime   string                 `gorm:"column:complete_time" json:"complete_time" bson:"complete_time"`
	ImageScanVuln  ImageScanSummaryResult `gorm:"-" json:"image_scan_vuln" bson:"-"`
	Container      []AssetContainer       `gorm:"-" json:"container" bson:"-"`
	ScanStatus     string                 `gorm:"-" json:"scan_status" bson:"-"`
	ImageScanVirus []VirusFileInfo        `gorm:"-" json:"image_scan_virus" bson:"-"`

	// CreateTime     string                 `gorm:"column:create_time" json:"create_time" bson:"create_time"`
	// PushTime     string         `gorm:"column:push_time;index" json:"push_time" bson:"push_time"`
	OnLineCount   int  `gorm:"column:on_line_count;default:0" json:"-"`
	Status        int  `gorm:"column:status;default:0" json:"status"` //  status: -1 not ready images 0 normal status
	RegistryId    uint // 来源registry，id为registry表的id
	FirstPushTime time.Time
	LastPushTime  time.Time  `gorm:"not null"` // 上次push时间
	LastPullTime  time.Time  // 上次pull时间
	ManifestV1    ManifestV1 `gorm:"-" json:"manifest_v1" `
	ManifestV2    ManifestV2 `gorm:"-" json:"manifest_v2"`
	ConfigFile    ConfigFile `gorm:"-" json:"config"`

	ManifestV1JSON datatypes.JSON `gorm:"type:jsonb"` // manifest内容
	ManifestV2JSON datatypes.JSON `gorm:"type:jsonb"`
	ConfigJson     datatypes.JSON `gorm:"type:jsonb"` // config内容,包括layer diffid
}

func (i ImageList) TableName() string {
	return "tensor_image_list"
}

// ImageRelate 镜像关联信息表
type ImageRelate struct {
	ID          int64  `gorm:"primary_key,AUTO_INCREMENT" json:"id" `
	Digest      string `gorm:"uniqueIndex:digest_library,priority:1" json:"digest"`
	Library     string `gorm:"uniqueIndex:digest_library,priority:2" json:"library"`
	ContainerID string `gorm:"column:container_id;uniqueIndex:digest_library,priority:3" json:"container_id"`
}

func (i ImageRelate) TableName() string {
	return "image_relate"
}

// Package Package表
type Package struct {
	PostModel
	PkgName     string `gorm:"index:pkg_index"`
	PkgVersion  string `gorm:"index:pkg_index"`
	VulnName    string `gorm:"index:pkg_index"`
	ImageDigest string `gorm:"index:pkg_index"`
}

// Registry Registry表
type Registry struct {
	ID          uint `gorm:"primaryKey"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   int
	Url         string `gorm:"index"` // 如:docker.io/v2, quay.io/v2
	Username    string // user for login registry
	Password    []byte // DES加密
	TLS         int    // 1-use tls,0-not use
	Token       string
	Description string
	ApiVersion  string
	AuthStr     string `gorm:"-" json:"auth_str"` // 用户名和密码加密后的数据，不存入数据库中
}

func (Registry) TableName() string {
	return "registries"
}

// ConfigFile is the configuration file that holds the metadata describing
// how to launch a container. See:
// https://github.com/opencontainers/image-spec/blob/master/config.md
//
// docker_version and os.version are not part of the spec but included
// for backwards compatibility.
type ConfigFile struct {
	Architecture  string    `json:"architecture"`
	Author        string    `json:"author,omitempty"`
	Container     string    `json:"container,omitempty"`
	Created       time.Time `json:"created,omitempty"`
	DockerVersion string    `json:"docker_version,omitempty"`
	History       []History `json:"history,omitempty"`
	OS            string    `json:"os"`
	RootFS        RootFS    `json:"rootfs"`
	Config        Config    `json:"config"`
	OSVersion     string    `json:"os.version,omitempty"`
}

// History is one entry of a list recording how this container image was built.
type History struct {
	Author     string    `json:"author,omitempty"`
	Created    time.Time `json:"created,omitempty"`
	CreatedBy  string    `json:"created_by,omitempty"`
	Comment    string    `json:"comment,omitempty"`
	EmptyLayer bool      `json:"empty_layer,omitempty"`
}

// RootFS returns Image's RootFS description including the layer IDs.
type RootFS struct {
	Type      string
	Layers    []string `json:",omitempty"`
	BaseLayer string   `json:",omitempty"`
}

// Config is a submessage of the config file described as:
//   The execution parameters which SHOULD be used as a base when running
//   a container using the image.
// The names of the fields in this message are chosen to reflect the JSON
// payload of the Config as defined here:
// https://git.io/vrAET
// and
// https://github.com/opencontainers/image-spec/blob/master/config.md
type Config struct {
	AttachStderr    bool                `json:"AttachStderr,omitempty"`
	AttachStdin     bool                `json:"AttachStdin,omitempty"`
	AttachStdout    bool                `json:"AttachStdout,omitempty"`
	Cmd             []string            `json:"Cmd,omitempty"`
	Healthcheck     *HealthConfig       `json:"Healthcheck,omitempty"`
	Domainname      string              `json:"Domainname,omitempty"`
	Entrypoint      []string            `json:"Entrypoint,omitempty"`
	Env             []string            `json:"Env,omitempty"`
	Hostname        string              `json:"Hostname,omitempty"`
	Image           string              `json:"Image,omitempty"`
	Labels          map[string]string   `json:"Labels,omitempty"`
	OnBuild         []string            `json:"OnBuild,omitempty"`
	OpenStdin       bool                `json:"OpenStdin,omitempty"`
	StdinOnce       bool                `json:"StdinOnce,omitempty"`
	Tty             bool                `json:"Tty,omitempty"`
	User            string              `json:"User,omitempty"`
	Volumes         map[string]struct{} `json:"Volumes,omitempty"`
	WorkingDir      string              `json:"WorkingDir,omitempty"`
	ExposedPorts    map[string]struct{} `json:"ExposedPorts,omitempty"`
	ArgsEscaped     bool                `json:"ArgsEscaped,omitempty"`
	NetworkDisabled bool                `json:"NetworkDisabled,omitempty"`
	MacAddress      string              `json:"MacAddress,omitempty"`
	StopSignal      string              `json:"StopSignal,omitempty"`
	Shell           []string            `json:"Shell,omitempty"`
}

// HealthConfig holds configuration settings for the HEALTHCHECK feature.
type HealthConfig struct {
	// Test is the test to perform to check that the container is healthy.
	// An empty slice means to inherit the default.
	// The options are:
	// {} : inherit healthcheck
	// {"NONE"} : disable healthcheck
	// {"CMD", args...} : exec arguments directly
	// {"CMD-SHELL", command} : run command with system's default shell
	Test []string `json:",omitempty"`

	// Zero means to inherit. Durations are expressed as integer nanoseconds.
	Interval    time.Duration `json:",omitempty"` // Interval is the time to wait between checks.
	Timeout     time.Duration `json:",omitempty"` // Timeout is the time to wait before considering the check to have hung.
	StartPeriod time.Duration `json:",omitempty"` // The start period for the container to initialize before the retries starts to count down.

	// Retries is the number of consecutive failures needed to consider a container as unhealthy.
	// Zero means inherit.
	Retries int `json:",omitempty"`
}

// Manifest represents the OCI image manifest in a structured way.
type ManifestV2 struct {
	SchemaVersion int64             `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// Descriptor holds a reference from the manifest to one of its constituent elements.
type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Size        int64             `json:"size"`
	Digest      string            `json:"digest"` // 这里原来是Hash结构
	URLs        []string          `json:"urls,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Platform    *Platform         `json:"platform,omitempty"`
}

// Hash is an unqualified digest of some content, e.g. sha256:deadbeef
type Hash struct {
	// Algorithm holds the algorithm used to compute the hash.
	Algorithm string

	// Hex holds the hex portion of the content hash.
	Hex string
}

func (h *Hash) String() string {
	return h.Algorithm + ":" + h.Hex

}

// Platform describes the platform which the image in the manifest runs on.
type Platform struct {
	// Architecture field specifies the CPU architecture, for example
	// `amd64` or `ppc64`.
	Architecture string `json:"architecture"`

	// OS specifies the operating system, for example `linux` or `windows`.
	OS string `json:"os"`

	// OSVersion is an optional field specifying the operating system
	// version, for example on Windows `10.0.14393.1066`.
	OSVersion string `json:"os.version,omitempty"`

	// OSFeatures is an optional field specifying an array of strings,
	// each listing a required OS feature (for example on Windows `win32k`).
	OSFeatures []string `json:"os.features,omitempty"`

	// Variant is an optional field specifying a variant of the CPU, for
	// example `v7` to specify ARMv7 when architecture is `arm`.
	Variant string `json:"variant,omitempty"`
}

type ManifestV1 struct {
	// Name is the name of the image's repository
	Name string `json:"name"`

	// Tag is the tag of the image specified by this manifest
	Tag string `json:"tag"`

	// Architecture is the host architecture on which this image is intended to
	// run
	Architecture string `json:"architecture"`

	// FSLayers is a list of filesystem layer blobSums contained in this image
	FSLayers []FSLayerV1 `json:"fsLayers"`

	// History is a list of unstructured historical data for v1 compatibility
	History   []map[string]string `json:"history"`
	HistoryV1 []HistoryV1         `json:"historyv1"`
}

type FSLayerV1 struct {
	BlobSum string `json:"blobSum"`
}

type HistoryV1 struct {
	Throwaway       bool              `json:"throwaway"`
	Created         time.Time         `json:"created"` // "2020-12-22T18:04:24.760519058Z",
	LayerDegest     string            `json:"id"`
	ContainerConfig ContainerConfigV1 `json:"container_config"`
}

type ContainerConfigV1 struct {
	Cmd []string `json:"Cmd"`
}

// 恶意文件
type Malicious struct {
	VirusInfo VirusInfo `json:"virus_info"`
}
