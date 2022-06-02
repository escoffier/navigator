package model

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gobwas/glob"
	json "github.com/json-iterator/go"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnnvd"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnvd"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type VulnMatedata struct {
	CVSS   CVSSVulnerabilityInfo   `json:"cvss,omitempty" bson:"cvss,omitempty"`
	CNNVDs cnnvd.VulnerabilityInfo `json:"cnnvds,omitempty" bson:"cnnvds,omitempty"`
	CNVDs  []cnvd.Metadata         `json:"cnvds,omitempty" bson:"cnvds,omitempty"`
}

type CnvdMetadatas []cnvd.Metadata

func (cm CnvdMetadatas) Len() int {
	return len(cm)
}

func weights(cm cnvd.Metadata) int {
	return len(cm.Severity)*10 + len(cm.RefLink)*100 + len(cm.Title)*1000 + len(cm.Number)*10000 + len(cm.Description)*100000
}

func (cm CnvdMetadatas) Less(i, j int) bool {
	return weights(cm[i]) >= weights(cm[j])
}

func (cm CnvdMetadatas) Swap(i, j int) {
	cm[i], cm[j] = cm[j], cm[i]
}

type PostModel struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt int
}

// 漏洞表
type Vuln struct {
	ID           int64         `gorm:"primaryKey" json:"id"`
	CreatedAt    time.Time     `json:"created_at" json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at" json:"updated_at"`
	DeletedAt    int           `json:"deleted_at" json:"deleted_at"`
	Target       string        `gorm:"column:target" json:"target"`
	Name         string        `gorm:"type:varchar(255);uniqueIndex:uniq_idx_vuln,priority:1" json:"name"` // 形如CVE-2021-28831
	Namespace    string        `gorm:"type:varchar(255)" json:"namespace"`                                 // 发行版名字：alpine，redhat等
	Description  string        `gorm:"type:text" json:"description"`                                       // 描述
	Link         []string      `gorm:"-" json:"link"`                                                      // 参考链接
	LinkJSON     []byte        `gorm:"type:Blob" json:"-"`
	Severity     string        `gorm:"type:varchar(255)" json:"severity"` // 威胁等级
	SeverityInt  int           `gorm:"column:severity_int" json:"severity_int"`
	Metadata     *VulnMatedata `gorm:"-" json:"metadata"`
	MetadataJSON []byte        `gorm:"type:Blob" json:"-"`                                                        // 元数据
	PkgName      string        `gorm:"type:varchar(255);uniqueIndex:uniq_idx_vuln,priority:2" json:"pkg_name"`    // 软件包来源
	PkgVersion   string        `gorm:"type:varchar(255);uniqueIndex:uniq_idx_vuln,priority:3" json:"pkg_version"` // 软件包版本
	FixedBy      string        `gorm:"type:varchar(255)" json:"fixedby"`                                          // 修复建议
	UniqueVuln   uint64        `gorm:"column:unique_vuln" json:"unique_vuln,string"`
	ExtraInfo    []byte        `gorm:"type:Blob" json:"-"` //  预留，漏洞属性。如我们自己的漏洞评级
	CheckSum     uint64        `gorm:"column:check_sum" json:"check_sum,string"`
	Class        string        `gorm:"column:target" json:"class"`      // 代表是系统包还是语言包 os-pkgs
	Language     string        `gorm:"column:language" json:"language"` // 把编程语言入库用于搜索 统一存小写，便于搜索
	Frame        string        `gorm:"column:frame" json:"frame"`       // 开发框架筛选
}

func (Vuln) TableName() string {
	return "ivan_scanner_vulns"
}
func (vn *Vuln) Serialize() {
	if vn.Metadata != nil {
		sort.Sort(CnvdMetadatas(vn.Metadata.CNVDs))
		bys, err := json.Marshal(vn.Metadata)
		if err != nil {
			logging.GetLogger().Err(err).Msg("Vuln.Serialize")
		} else {
			vn.MetadataJSON = bys
		}
	}
	if len(vn.Link) > 0 {
		sort.Strings(vn.Link)
		bys, err := json.Marshal(vn.Link)
		if err != nil {
			logging.GetLogger().Err(err).Msg("Vuln.Serialize")
		} else {
			vn.LinkJSON = bys
		}
	}
	if vn.Language == "" {
		vn.Language = GetVulnLanguageMap()[vn.Namespace] // 如果没有编程语言，就存空
	}

	if vn.Language == "java" {
		if strings.Contains(vn.PkgName, "struts2") {
			vn.Frame = "struts2"
		}
		if strings.Contains(vn.PkgName, "fastjson") {
			vn.Frame = "fastjson"
		}
	}
}

func (vn *Vuln) Deserialize() {
	if len(vn.MetadataJSON) > 0 {
		meta := VulnMatedata{}
		if err := json.Unmarshal(vn.MetadataJSON, &meta); err != nil {
			logging.GetLogger().Err(err).Msg("Vuln.Deserialize")
			meta = VulnMatedata{} // 一定改成默认值
		}
		vn.Metadata = &meta
	}

	if len(vn.LinkJSON) > 0 {
		link := make([]string, 0)
		if err := json.Unmarshal(vn.LinkJSON, &link); err != nil {
			logging.GetLogger().Err(err).Msg("Vuln.Deserialize")
			link = make([]string, 0)
		}
		vn.Link = link
	}
}

func (vn *Vuln) GenCheckSum() uint64 {
	vn.Serialize()
	vn.Deserialize()
	createdAt, updatedAt, preCheck := vn.CreatedAt, vn.UpdatedAt, vn.CheckSum
	vn.CreatedAt = time.Time{}
	vn.UpdatedAt = time.Time{}
	vn.CheckSum = 0

	bys, err := json.Marshal(vn)
	vn.CreatedAt, vn.UpdatedAt, vn.CheckSum = createdAt, updatedAt, preCheck
	if err != nil {
		return 0
	}
	return util.GenerateUUID64(string(bys))
}

func (vn *Vuln) GenUniqueVuln() uint64 {
	key := fmt.Sprintf(consts.UniqueVulnFamat, vn.Name, vn.PkgName, vn.PkgVersion)
	uid := util.GenerateUUID64(key)
	return uid
}

// 漏洞关联镜像表
type VulnImage struct {
	ID         int64     `gorm:"primaryKey" json:"id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	UniqueVuln uint64    `gorm:"column:unique_vuln" json:"unique_vuln"`                      // 漏洞的唯一标识
	ImageId    int64     `gorm:"uniqueIndex:uniq_idx_vnlu_image,priority:2" json:"image_id"` // 镜像id
}

func (VulnImage) TableName() string {
	return "ivan_scanner_vuln_images"
}

type ScanLayer struct { // 层级扫描结果
	ID           uint      `gorm:"primaryKey" json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	DeletedAt    int       `json:"deleted_at"`
	ImageID      int64     `gorm:"column:image_id;uniqueIndex:uniq_idx_scan_layer,priority:1" json:"image_id"`
	LayerDigest  string    `gorm:"type:varchar(255);uniqueIndex:uniq_idx_scan_layer,priority:2" json:"layer_digest"`
	VulnInfoJSON []byte    `gorm:"type:longblob" json:"-"` // 包含扫描结果的json
	VulnInfo     []uint64  `gorm:"-" json:"vuln_info"`     // 对应vulns表的unique_vuln字段

	PkgInfoJSON []byte      `gorm:"type:longblob" json:"-"` // 软件包信息
	PkgInfo     interface{} `gorm:"-" json:"pkg_info"`

	MaliciousInfoJSON []byte      `gorm:"type:longblob" json:"-"`  // 恶意文件
	MaliciousInfo     []Malicious `gorm:"-" json:"malicious_info"` // 恶意文件

	WebshellInfoJSON []byte     `gorm:"type:longblob" json:"-"` // webshell
	WebshellInfo     []Webshell `gorm:"-" json:"webshell_info"` // webshell

	SensitiveFileJSON []byte      `gorm:"type:longblob" json:"-"` // 敏感文件
	SensitiveFile     []Sensitive `gorm:"-" json:"sensitive_file"`

	IsBasic int `json:"is_basic"`
}

func (ScanLayer) TableName() string {
	return "ivan_scanner_scan_layers"
}

func (sl *ScanLayer) Deserialize() {
	vuln := make([]uint64, 0)
	if len(sl.VulnInfoJSON) > 0 {
		if err := json.Unmarshal(sl.VulnInfoJSON, &vuln); err != nil {
			logging.GetLogger().Err(err).Msg("ScanLayer.Deserialize")
			// 解析出错，说明是老数据，做一下兼容，数据会在下一次扫描时写成新的格式
			vuln = make([]uint64, 0) // 重新初始化数据
			preVulns := make([]SingleScanDetail, 0)
			if err := json.Unmarshal(sl.VulnInfoJSON, &preVulns); err != nil {
				logging.GetLogger().Err(err).Msg("ScanLayer.Deserialize pre data")
			} else {
				for i := range preVulns {
					for j := range preVulns[i].Vulns {
						for k := range preVulns[i].Vulns[j].Trivy {
							vulnUnique := util.GenerateUUID64(fmt.Sprintf(consts.UniqueVulnFamat,
								preVulns[i].Vulns[j].CVEID,
								preVulns[i].Vulns[j].Trivy[k].PkgName,
								preVulns[i].Vulns[j].Trivy[k].InstalledVersion))

							vuln = append(vuln, vulnUnique)
						}
					}
				}
			}
		}
	}
	sl.VulnInfo = util.DeDuplicationUint64Slice(vuln)

	malic := make([]Malicious, 0)
	if len(sl.MaliciousInfoJSON) > 0 {
		if err := json.Unmarshal(sl.MaliciousInfoJSON, &malic); err != nil {
			logging.GetLogger().Err(err).Msg("ScanLayer.Deserialize")
			malic = make([]Malicious, 0)
		}
	}
	sl.MaliciousInfo = malic

	webshell := make([]Webshell, 0)
	if len(sl.MaliciousInfoJSON) > 0 {
		if err := json.Unmarshal(sl.WebshellInfoJSON, &webshell); err != nil {
			logging.GetLogger().Err(err).Msg("ScanLayer.Deserialize")
			webshell = make([]Webshell, 0)
		}
	}
	sl.WebshellInfo = webshell

	sensitiveFile := make([]Sensitive, 0)
	if len(sl.SensitiveFileJSON) > 0 {
		if err := json.Unmarshal(sl.SensitiveFileJSON, &sensitiveFile); err != nil {
			logging.GetLogger().Err(err).Msg("ScanLayer.Deserialize")
			sensitiveFile = make([]Sensitive, 0)
		}
	}
	sl.SensitiveFile = sensitiveFile
}

func (sl *ScanLayer) Serialize() {
	if len(sl.VulnInfo) > 0 {
		sl.VulnInfo = util.DeDuplicationUint64Slice(sl.VulnInfo)
		if bys, err := json.Marshal(sl.VulnInfo); err != nil {
			logging.GetLogger().Err(err).Msg("ScanLayer.Serialize")
		} else {
			sl.VulnInfoJSON = bys
		}
	}

	if len(sl.MaliciousInfo) > 0 {
		if bys, err := json.Marshal(sl.MaliciousInfo); err != nil {
			logging.GetLogger().Err(err).Msg("ScanLayer.Serialize")
		} else {
			sl.MaliciousInfoJSON = bys
		}
	}
	if len(sl.WebshellInfo) > 0 {
		if bys, err := json.Marshal(sl.WebshellInfo); err != nil {
			logging.GetLogger().Err(err).Msg("ScanLayer.Serialize")
		} else {
			sl.WebshellInfoJSON = bys
		}
	}
	if len(sl.SensitiveFile) > 0 {
		if bys, err := json.Marshal(sl.SensitiveFile); err != nil {
			logging.GetLogger().Err(err).Msg("ScanLayer.Serialize")
		} else {
			sl.SensitiveFileJSON = bys
		}
	}
}

// Package Package表
type Package struct {
	PostModel
	PkgName     string `gorm:"type:varchar(255);index:pkg_index"`
	PkgVersion  string `gorm:"type:varchar(255);index:pkg_index"`
	VulnName    string `gorm:"type:varchar(255);index:pkg_index"`
	ImageDigest string `gorm:"type:varchar(255);index:pkg_index"`
}

func (Package) TableName() string { return "ivan_scanner_package" }

// Registry Registry表
type Registry struct {
	ID             int64  `gorm:"primaryKey" json:"id"`
	Name           string `gorm:"type:varchar(255);uniqueIndex:uniq_idx_registry_name;priority:1" json:"name"` // 仓库名字,仓库名是仓库的唯一标识,一个仓库名称  对应一个用户
	RegType        string `gorm:"type:varchar(255);column:reg_type" json:"reg_type"`                           // 仓库类型
	Url            string `gorm:"type:varchar(255);column:url" json:"url"`                                     // 如:docker.io/v2, quay.io/v2
	Username       string `gorm:"type:varchar(255);column:username" json:"username"`                           // user for login registry
	Password       []byte `gorm:"type:blob" json:"-"`                                                          // DES加密
	PasswordString string `gorm:"-" json:"password"`
	Token          string `gorm:"-" json:"token"`
	Description    string `gorm:"type:varchar(255);column:description"  json:"description"`
	AuthStr        string `gorm:"-" json:"auth_str"`                                  // 用户名和密码加密后的数据，不存入数据库中
	UseType        int    `gorm:"column:use_type" json:"-"`                           // 1-用户仓库,2-buf仓库
	SyncInterval   int64  `gorm:"column:sync_interval" json:"sync_interval"`          // 单位：分钟
	LastSyncAt     int64  `gorm:"column:last_sync_at; default:0" json:"last_sync_at"` // 最后一次同步时间
	AccessKey      string `gorm:"access_key" json:"access_key"`                       // 阿里云仓库的AccessKey
	AccessSecret   string `gorm:"access_secret" json:"access_secret"`                 // 阿里云仓库的AccessSecret
	InstanceID     string `gorm:"instance_id" json:"instance_id"`                     // 阿里云仓库企业版实例ID
	RegionID       string `gorm:"region_id" json:"region_id"`                         // 阿里云仓库企业版地域ID

	CreatedAt time.Time `gorm:"column:created_at" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at" json:"updated_at"`
	DeletedAt int64     `gorm:"column:deleted_at; default:0;uniqueIndex:uniq_idx_registry_name;priority:2" json:"deleted_at"`
}

func (r *Registry) WhetherToStartSync() bool {
	if r.LastSyncAt == 0 {
		return true
	}

	now := time.Now().Unix()

	if r.LastSyncAt+r.SyncInterval*60 < now {
		return false
	}
	return true
}

func (Registry) TableName() string {
	return "ivan_scanner_registries"
}

func (r *Registry) Validate(valTY string) error {

	if strings.Trim(r.Name, " ") == "" {
		return errors.New("no name")
	}
	if strings.Trim(r.Username, " ") == "" {
		return errors.New("no username")
	}
	if strings.Trim(r.PasswordString, " ") == "" {
		return errors.New("no password")
	}
	if r.SyncInterval <= 0 {
		return errors.New("SyncInterval must than 0")
	}
	if valTY == consts.ValidateCreate {
		if r.Url == "" && len([]rune(r.Url)) > 255 {
			return errors.New("registry address is illegal")
		}
	}
	return nil
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

// ManifestV2 represents the OCI image manifest in a structured way.
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
	VirusInfo VirusInfo `json:"virus_info,omitempty"`
}

type Webshell struct {
	WebShellInfo WebShellInfo `json:"webshell_info,omitempty"`
}

// RejectRecord 拦截记录表
type RejectRecord struct {
	ID           int64  `json:"id"`
	Library      string `json:"library"`                                                                    // 仓库名
	FullRepoName string `gorm:"type:varchar(255);index:idx_reject_record,priority:1" json:"full_repo_name"` // 镜像名
	Tag          string `gorm:"type:varchar(255);index:idx_reject_record,priority:2" json:"tag"`            // 版本号
	RejectDetail string `gorm:"type:varchar(255);" json:"reject_detail"`                                    // 阻断原因(详细)用|分隔
	// RejectReasonJson []byte    `gorm:"type:MediumBlob;column:reject_reason_json" json:"-"`                         // 阻断原因(大类) {"1":"1"}
	RejectReason []int64   `gorm:"-" json:"reject_reason"` // 阻断原因(大类)
	ReasonFlag   uint64    `gorm:"column:reason_flag" json:"reason_flag"`
	VulnScore    int64     `json:"vuln_score"`                           // 被阻断时设置的策略漏洞评分
	VulnLevel    string    `gorm:"type:varchar(255);" json:"vuln_level"` // 被阻断时设置的策略漏洞评级
	Digest       string    `gorm:"type:varchar(255);" json:"digest"`
	RejectAt     time.Time `gorm:"index"  json:"reject_at"` // 阻断时间
	CreatedAt    time.Time `json:"created_at"`              // 创建时间
	DeletedAt    int       `json:"deleted_at,omitempty"`
}

func (rr *RejectRecord) Deserialize() *RejectRecord {
	re := make([]int64, 0)
	for i := range GetRejectReason(LangZh) {
		if ExistFlag(rr.ReasonFlag, i) {
			re = append(re, i)
		}
	}

	rr.RejectReason = re
	return rr
}

func (RejectRecord) TableName() string {
	return "ivan_scanner_reject_record"
}

func (rr *RejectRecord) GenReasonFlag() uint64 {
	res := GetRejectReason(LangZh)
	var flag uint64
	rr.RejectReason = util.DeDuplicationInt64Slice(rr.RejectReason)
	for _, r := range rr.RejectReason {
		if _, ok := res[r]; ok {
			flag = 1<<r + flag
		}
	}
	rr.ReasonFlag = flag
	return flag
}

// ImageWhitelist 镜像白名单
type ImageWhitelist struct {
	ID           int64     `json:"id"`
	Library      string    `gorm:"type:varchar(255);uniqueIndex:uniq_idx_white_image,priority:3" json:"library"`        // 仓库名
	FullRepoName string    `gorm:"type:varchar(255);uniqueIndex:uniq_idx_white_image,priority:1" json:"full_repo_name"` // 镜像名
	Tag          string    `gorm:"type:varchar(255);uniqueIndex:uniq_idx_white_image,priority:2" json:"tag"`            // 版本号
	Digest       string    `gorm:"type:varchar(255);" json:"digest"`
	CreatedAt    time.Time `json:"created_at"` //
}

func (ImageWhitelist) TableName() string {
	return "ivan_scanner_image_whitelist"
}

// RejectPolicy 阻断策略表
type RejectPolicy struct {
	ID          int64    `json:"id"`
	Name        string   `gorm:"type:varchar(255);" json:"name"` // 策略名
	Library     []string `gorm:"-" json:"library"`               // 生效仓库名
	LibraryJSON []byte   `gorm:"type:blob;column:library_json" json:"-"`
	Comment     string   `gorm:"type:varchar(255);" json:"comment"`  // 备注
	Operator    string   `gorm:"type:varchar(255);" json:"operator"` // 操作员名字

	VulnScore     int64  `json:"vuln_score"`                            // 漏洞按分数阻断(低于多少分后阻断)
	VulnLevel     string `gorm:"type:varchar(255);" json:"vuln_level"`  // 漏洞按严重级别阻断
	VulnPolicy    string `gorm:"type:varchar(255);" json:"vuln_policy"` //
	WebShellScore int64  `json:"web_shell_score"`

	WebShellPolicy       string `gorm:"type:varchar(255);" json:"web_shell_policy"`
	SensitiveFilePolicy  string `gorm:"type:varchar(255);" json:"sensitive_file_policy"`       // 敏感文件规则
	MaliciousPolicy      string `gorm:"type:varchar(255);" json:"malicious_policy"`            // 恶意文件规则
	BaseImagePolicy      string `gorm:"type:varchar(255);" json:"base_image_policy"`           // 基础镜像规则
	TrustedImagePolicy   string `gorm:"type:varchar(255);" json:"trusted_image_policy"`        // 可信镜像规则
	PrivilegedBootPolicy string `gorm:"type:varchar(255);" json:"privileged_boot_policy"`      // 特权启动规则
	EnvPolicy            string `gorm:"type:varchar(255);column:env_policy" json:"env_policy"` // 环境变量

	SensitiveFileJson string                `gorm:"type:text;column:sensitive_file" json:"-"`
	SensitiveFile     []SensitiveFilePolicy `gorm:"-" json:"sensitive_file"`
	EnvsJson          string                `gorm:"type:text;column:envs" json:"-"`
	Envs              []string              `gorm:"-" json:"envs"`
	CicdEnable        bool                  `gorm:"cicd_enable" json:"cicd_enable"`
	K8sEnable         bool                  `gorm:"k8s_enable" json:"k8s_enable"`
	RejectVulns       []RejectVuln          `gorm:"-" json:"reject_vulns"`
	Mode              string                `gorm:"type:varchar(255);column:mode" json:"mode"` // 阻断模式(基本模式,安全模式)
	OnlineMonitor     bool                  `gorm:"online_monitor" json:"online_monitor"`      // 是否开启在线监控
	CreatedAt         time.Time             `json:"created_at"`                                //
	UpdatedAt         time.Time             `json:"updated_at"`
	Enable            bool                  `json:"enable"` // 是否启用该策略
	IsGlobal          bool                  `json:"is_global"`
	DeletedAt         int                   `json:"deleted_at,omitempty"`
} // @name RejectPolicy

type SensitiveFilePolicy struct {
	Key    string `json:"key"`
	Policy string `json:"policy"`
}

func (RejectPolicy) TableName() string {
	return "ivan_scanner_reject_policy"
}

// RejectVuln 自定义的镜像阻断
type RejectVuln struct {
	ID             int64     `json:"id"`
	RejectPolicyID int64     `gorm:"uniqueIndex:uniq_idx_reject_vuln,priority:1" json:"reject_policy_id"`
	Library        string    `gorm:"type:varchar(255);uniqueIndex:uniq_idx_reject_vuln,priority:2" json:"library"` // 生效仓库名
	Name           string    `gorm:"type:varchar(255);uniqueIndex:uniq_idx_reject_vuln,priority:3" json:"name"`    // 形如CVE-2021-28831
	RejectPolicy   string    `gorm:"type:varchar(255)" json:"reject_policy"`                                       // 阻断动作
	CreatedAt      time.Time `json:"created_at"`
}

func (RejectVuln) TableName() string {
	return "ivan_scanner_reject_vuln"
}

// Task define scan dimension
type Task struct {
	ID                  int64      `json:"id"`
	ScopeType           int        `gorm:"scope_type" json:"scope_type"`         // full-scan or partial-scan
	SubTaskCount        int        `gorm:"sub_task_count" json:"sub_task_count"` // subtask count
	Trigger             int        `gorm:"trigger" json:"trigger"`               // 扫描类型， 1:cicd 2:漏洞库更新 3:病毒库更新 4:周期 5:手动
	FlowConf            string     `gorm:"type:varchar(255);column:flow_conf" json:"flow_conf"`
	Priority            int        `gorm:"priority" json:"priority"`
	Status              int        `gorm:"status" json:"status"`
	Result              int        `gorm:"result" json:"result"`
	Msg                 string     `gorm:"type:varchar(255);column:msg" json:"msg"`
	Comment             string     `gorm:"type:varchar(255);column:comment" json:"comment"`
	CreatedAt           time.Time  `gorm:"created_at" json:"created_at"`           // task create time
	StartedAt           *time.Time `gorm:"column:started_at:" json:"started_at"`   // task start time
	FinishedAt          *time.Time `gorm:"column:finished_at:" json:"finished_at"` // task finish time
	UpdatedAt           time.Time  `gorm:"updated_at" json:"updated_at"`           // task update time
	HeartBeat           *time.Time `gorm:"heart_beat" json:"heart_beat"`
	Operator            string     `gorm:"type:varchar(255);column:operator" json:"operator"`
	PolicyId            int64      `gorm:"policy_id" json:"policy_id"`                            // scan type,scan scope,detail policy info in policy table
	ScannerId           string     `gorm:"type:varchar(255);column:scanner_id" json:"scanner_id"` // scanner uuid
	ScanStrategyName    string     `gorm:"-" json:"scan_strategy_name"`
	SuccessSubTaskCount int        `gorm:"-" json:"success_sub_task_count"` // 成功的子任务数量

}

func (Task) TableName() string {
	return "ivan_scanner_scan_task"
}

type SubTask struct {
	ID         int64      `json:"id"`
	TaskID     int64      `gorm:"column:task_id;index:task_id_idx" json:"task_id"`
	ImageID    int64      `gorm:"image_id" json:"image_id"` // image id in db
	Status     uint8      `gorm:"status" json:"status"`     // 1:pending,2:inprogress,3:scan success,4:scan failed
	Result     uint8      `gorm:"result" json:"result"`     // deprecated,1:failed, 2:success
	ErrMsg     string     `gorm:"type:varchar(255);column:err_msg" json:"err_msg"`
	ErrNo      int        `gorm:"column:err_no" json:"err_no"`
	ErrMsgEnu  string     `gorm:"-" json:"err_msg_enu"`         // 错误信息的枚举值，用于前端展示
	CreatedAt  time.Time  `gorm:"created_at" json:"created_at"` // subtask create time
	StartedAt  *time.Time `gorm:"started_at" json:"started_at"`
	UpdatedAt  time.Time  `gorm:"updated_at" json:"updated_at"`
	FinishedAt *time.Time `gorm:"finished_at" json:"finished_at"`
	HeartBeat  *time.Time `gorm:"heart_beat" json:"heart_beat"`
	RetryCount int        `gorm:"column:retry_count" json:"retry_count"`

	// 镜像的信息
	ImageInfo struct {
		FullRepoName string `gorm:"-" json:"full_repo_name"` // eg:library/redis,may not use,could fetch by image list table
		Tag          string `gorm:"-" json:"tag"`            // eg:1.10, may not use
		Library      string `gorm:"-" json:"library"`        // registry name
	} `gorm:"-" json:"image_info"`
}

func (SubTask) TableName() string {
	return "ivan_scanner_scan_subtask"
}

// ImageRsa 用于保存可信镜像的RSA公钥和匹配规则
type ImageRsa struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at"`

	RsaId            string `gorm:"type:varchar(255);column:rsa_id;uniqueIndex:uqi_rsa_id;comment:唯一的ID;type:CHAR(14)" json:"rsa_id"`
	Name             string `gorm:"type:varchar(255);column:name;comment:名字;type:VARCHAR(50)" json:"name"`
	PrivateKeyDigest string `gorm:"type:varchar(255);column:private_key_digest;index:idx_prv_dig;type:CHAR(64);comment:私钥的sha256值" json:"private_key_digest"`
	PublicKey        string `gorm:"type:text;column:public_key;not null;comment:公钥的内容" json:"public_key"`
	Registry         string `gorm:"type:varchar(255);column:registry;comment:适用的仓库;default:''" json:"registry"`
	MatchRule        string `gorm:"type:varchar(255);column:match_rule;comment:匹配规则;default:''" json:"match_rule"`
	Comment          string `gorm:"type:varchar(255);column:comment;comment:说明;default:'';type:VARCHAR(150)" json:"comment"`
}

func (ImageRsa) TableName() string { return "ivan_scanner_image_rsa" }

var RsaNameCheck = regexp.MustCompile(`^[0-9a-zA-Z_]+$`)

func (i *ImageRsa) Check() error {
	if !RsaNameCheck.MatchString(i.Name) {
		return fmt.Errorf("密钥名称不符合格式")
	}

	if utf8.RuneCountInString(i.Comment) > 150 {
		return errors.New("密钥描述长度不能超过150")
	}

	if _, err := glob.Compile(i.MatchRule, '/'); err != nil {
		return errors.New("镜像规则错误")
	}
	return nil
}

// TrustedImages 记录可信镜像信息
type TrustedImages struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at"`

	Digest string `gorm:"type:varchar(255);column:digest;not null;uniqueIndex:uqi_digest;type:CHAR(71);comment:镜像的digest" json:"digest"`
	// 是否为可信镜像, 0为不可信, 1为可信
	IsTrusted uint8 `gorm:"column:is_trusted;default:0;comment:是否为可信,0为不可信,1为可信" json:"is_trusted"`
}

func (TrustedImages) TableName() string { return "ivan_scanner_trusted_images" }

type WebFrameScan struct {
	ID               uint           `gorm:"primaryKey" json:"id"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"deleted_at"`
	ImageUUID        uint32         `gorm:"column:image_uuid" json:"-"`
	WebFrameInfoJSON []byte         `gorm:"type:mediumblob;column:web_frame_info" json:"-"`
	WebFrameInfos    []WebFrameInfo `gorm:"-" json:"web_frame_info"`
}

func (WebFrameScan) TableName() string { return "ivan_scanner_web_frame_scan" }

type SyncRetryImage struct {
	ID           int64     `gorm:"primaryKey" json:"id"`
	UniqueImage  uint64    `gorm:"column:unique_image" json:"unique_image,string"` // 由fullreponame+tags+registryId+fromType生成uuid，唯一确定一定镜像，优化查询
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	FullRepoName string    `gorm:"column:full_repo_name" json:"fullRepoName"`
	Tag          string    `gorm:"column:tag" json:"tag"`
	Message      string    `gorm:"column:message" json:"message"`
	RegistryID   int64     `gorm:"registry_id" json:"registryId"`
	RetryCount   int64     `gorm:"column:retry_count" json:"retryCount"`
}

func (sri *SyncRetryImage) GenUniqueImage() uint64 {
	uid := util.GenerateUUID64(fmt.Sprintf(consts.UniqueImageFamat, sri.FullRepoName, sri.Tag, 0, sri.RegistryID))
	return uid
}

func (SyncRetryImage) TableName() string { return "ivan_scanner_sync_retry_image" }
