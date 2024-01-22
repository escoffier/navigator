package imagesec

import (
	"fmt"
	"strings"
	"time"

	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
)

// ImageMeta 镜像的元数据
type ImageMeta struct {
	UniqueID  uint64   `json:"uniqueID"`
	ImageId   string   `json:"imageId"`   // 镜像id。docker 为镜像生成的id，非digest。
	Digests   []string `json:"digests"`   // 镜像digest,如果镜像为本地构建，可能为空.e.g.nginx@sha256:xxx
	RepoTags  []string `json:"repoTags"`  // 镜像repo，如 library/dev。数组.若一个镜像多次本地构建，则历史镜像的repoTags信息为空
	Os        string   `json:"os"`        // 镜像操作系统信息，如：ubuntu:20.04
	Namespace string   `json:"namespace"` // 镜像所在的 namespace
	Size      int64    `json:"size"`      // 镜像大小,byte
	Layers    []Layer  `json:"layers"`    // layer信息,docker 通过history api获取
	ENVS      []string `json:"envs"`      // 镜像的环境变量
	User      string   `json:"user"`      // 镜像的user
	Created   string   `json:"created"`   // RFC 3339 format with nano-seconds.e.g."2022-02-04T21:20:12.497794809Z"
	PullCount int64    `json:"pullCount"` // 镜像的下载次数
}

func (vi *ImageMeta) LogStr() string {
	na := strings.Join(vi.RepoTags, ",")
	return na
}

// Layer 镜像层级，兼顾docker history结果和registry的layer
type Layer struct {
	Comment   string `json:"comment,omitempty"`
	Created   int64  `json:"created,omitempty"`   // 镜像layer创建时间,unix time stamp
	CreatedBy string `json:"createdBy,omitempty"` // 创建的命令,如：RUN apt-get install bash
	Size      int64  `json:"size"`                // 镜像layer大小
	Digest    string `json:"digest,omitempty"`    // 镜像layer标识。对registry的manifest文件，此值为layer的sha256值。对docker api，为docker自定义的id
	DiffID    string `json:"diffID,omitempty"`
}

// NodeReport 节点上报数据，包括节点信息，镜像数据
type NodeReport struct {
	UUID            string          `json:"uuid"`       // 每次上报的唯一id，用于和scanner对齐数据
	NodeInfo        NodeInfo        `json:"nodeInfo"`   // 节点信息
	NodeImages      []ImageMeta     `json:"nodeImages"` // 节点上所有的镜像
	RegImages       []ImageMeta     `json:"libImages"`  // 仓库同步镜像镜像
	RegInfo         RegInfo         `json:"regInfo"`
	ReportedAt      int64           `json:"reportedAt"` // 上报时间点
	ReportDBVersion ReportDBVersion `json:"reportDBVersion"`
}

func (v *NodeReport) LogStr() string {
	ans := make([]string, 0)
	ans = append(ans, fmt.Sprintf("uuid=%s", v.UUID))
	if v.NodeInfo.ClusterKey != "" {
		ans = append(ans, fmt.Sprintf("nodeInfo=%v", v.NodeInfo))
	}
	if v.RegInfo.RegID > 0 {
		ans = append(ans, fmt.Sprintf("regInfo=%v", v.RegImages))
	}
	for i := range v.NodeImages {
		im := v.NodeImages[i]
		ans = append(ans, fmt.Sprintf("repoTags=%s", strings.Join(im.RepoTags, ";")))
		ans = append(ans, fmt.Sprintf("Digests=%s", strings.Join(im.Digests, ";")))
	}
	for i := range v.RegImages {
		im := v.RegImages[i]
		ans = append(ans, fmt.Sprintf("repoTags=%s", strings.Join(im.RepoTags, ";")))
		ans = append(ans, fmt.Sprintf("Digests=%s", strings.Join(im.Digests, ";")))
	}
	return strings.Join(ans, ";")
}

// ScanSubTask 节点镜像 扫描任务的子任务，即单个镜像
type ScanSubTask struct {
	TaskID         int64         `json:"taskID"`        // 任务id
	SubTaskID      int64         `json:"subTaskID"`     // 子任务id,因为任务可以重新调度,所以不能使用 SubTaskID 来确认一次唯一的扫描任务
	NodeInfo       NodeInfo      `json:"nodeInfo"`      // 镜像所属节点，用于校验
	NodeImageMeta  ImageMeta     `json:"nodeImageMeta"` // 节点镜像元数据
	RegImageMeta   ScanImageMeta `json:"regImageMeta"`  // 仓库镜像元数据
	ScanInstance   ScanInstance  `json:"scanInstance"`  // scanInstance
	RegInfo        RegInfo       `json:"regInfo"`
	SensitiveRules []string      `json:"sensitiveRules"` // 扫描所用的敏感文件规则规则（不包含默认敏感文件规则）
	DBVersion      RuleVersion   `json:"dbVersion"`      // 主集群下发任务时，当前所使用的版本号
	UniqueID       string        `json:"uuid"`           // 生成方式 taskID+SubtaskID+time.Now().UnixMilli()
	ScanTimeout    int64         `json:"scanTimeout"`    // 单位 秒
	WebshellCache  LayerInCache  `json:"webshellCache"`
	VulnCache      LayerInCache  `json:"vulnCache"`
	LicenseCache   LayerInCache  `json:"licenseCache"`
	SensitiveCache LayerInCache  `json:"sensitiveCache"`
	MalwareCache   LayerInCache  `json:"malwareCache"`
	DeepScan       bool          `json:"deepScan"`
}

type RuleVersion struct {
	Sensitive string
	Vuln      string
	Webshell  string
	Avira     string
	License   string
}

type LayerInCache map[string]bool

type Cache struct {
	DBVersion string
}

func (vi LayerInCache) In(ly string) bool {
	if vi == nil {
		return false
	}
	return vi[ly]
}

func (vi *ScanSubTask) LogStr() string {
	s := fmt.Sprintf("task:%d-%d-%t", vi.TaskID, vi.SubTaskID, vi.DeepScan)
	// 说明是节点镜像
	if vi.NodeInfo.ClusterKey != "" {
		s = fmt.Sprintf("%s,node:%s,image:%s", s, vi.NodeInfo.LogStr(), vi.NodeImageMeta.LogStr())
	}
	// 说明是仓库镜像
	if vi.RegInfo.Username != "" {
		s = fmt.Sprintf("%s,reg:%s,image:%s/%s:%s", s, vi.RegInfo.Name, vi.RegImageMeta.Host, vi.RegImageMeta.Repo, vi.RegImageMeta.Tag)
	}

	return s
}

func (vi *ScanSubTask) GenUniqueID() string {
	vi.UniqueID = fmt.Sprintf("%d-%d-%d", vi.TaskID, vi.SubTaskID, time.Now().UnixMilli())
	return vi.UniqueID
}

// ReportScanResult 镜像扫描结果.trivy的扫描结果为一个数组，我们会把结果扁平化放到此结构体里。
type ReportScanResult struct {
	UUID             string                  `json:"uuid"`      // 每次扫描任务的唯一标识
	TaskID           int64                   `json:"taskID"`    // 对应的扫描任务id
	SubTaskID        int64                   `json:"subTaskID"` // 对应的子任务id
	ImageUniqueID    uint64                  `json:"imageUniqueID"`
	OS               types.OS                `json:"os"`
	Sensitives       SensitiveFileResults    `json:"sensitives"`        // 敏感文件
	Malware          MalwareResults          `json:"malware"`           // 恶意软件扫描结果
	Webshell         WebshellResults         `json:"webshell"`          // webshell 扫描结果
	License          []License               `json:"license,omitempty"` // 镜像使用的license 名
	WebFrameInfo     WebFrameInfo            `json:"webFrameInfo,omitempty"`
	StatusStr        string                  `json:"statusStr,omitempty"`
	Msg              string                  `json:"msg,omitempty"`
	OriginArtifact   []ftypes.ArtifactDetail `json:"originArtifact,omitempty"` // irene扫描结果中的artifact。scanner利用这里的软件包信息做漏洞匹配.为了方便而设置，和vulnResult相比有冗余数据
	Errors           []error                 `json:"-"`
	SaveFileToKafka  []SaveFileToKafka       `json:"-"`
	MalwareCache     []CacheScan             `json:"malwareCache,omitempty"`
	SensitiveCache   []CacheScan             `json:"sensitiveCache,omitempty"`
	LicenseCache     []CacheScan             `json:"licenseCache,omitempty"`
	WebshellCache    []CacheScan             `json:"webshellCache,omitempty"`
	VulnCache        []CacheScan             `json:"vulnCache,omitempty"`
	DBVersion        RuleVersion             `json:"dbVersion,omitempty"`        // 主集群下发任务时，当前所使用的版本号
	IgnoreVulnAndPkg bool                    `json:"ignoreVulnAndPkg,omitempty"` // 这个参数是为了做数据迁移及兼容老版本的扫描器
}

type CacheScan struct {
	Issue      string `json:"issue"`      // 结果类型
	CanInCache bool   `json:"canInCache"` // 扫描上报结果标识扫描没有出错，可以保存进入缓存，以供后续扫描所用
	InCache    bool   `json:"inCache"`    // 扫描上报结果标识已在缓存中，保存镜像结果时需要查询该缓存
	Layer      string `json:"layer"`      // 层级或镜像Digest
}

type ScanJobResult struct {
	OS              types.OS                `json:"os"`
	Sensitive       []SensitiveFile         `json:"sensitiveFiles"`
	ClamAvScan      []ClamAvScanResult      `json:"clamAvScan"`
	AviraScan       []AviraScanResult2      `json:"aviraScan"`
	Webshell        []HmWebshell            `json:"webshell"`
	License         []License               `json:"license"`
	OriginArtifact  []ftypes.ArtifactDetail `json:"originArtifact"`
	InCache         bool                    `json:"inCache"` // 下发任务时已说明结果存在于缓存中，保存镜像扫描结果时需要先查询缓存
	Scanned         bool                    `json:"scanned"` // 是否扫描过
	Errors          []error                 `json:"-"`
	SaveFileToKafka []SaveFileToKafka       `json:"-"`
	Layer           string                  `json:"layer"`
	Issue           string                  `json:"issue"`
	DBVersion       string                  `json:"dbVersion"` // 扫描job所用的版本号
}

func (vi *ReportScanResult) LogStr() string {
	s1 := fmt.Sprintf("task:%d-%d-%d", vi.TaskID, vi.SubTaskID, vi.ImageUniqueID)
	// 说明是节点镜像
	s2 := fmt.Sprintf("sensitive:%d,webshell:%d,malware:%d,license:%d,artifact:%d,seendFile:%d,status:%s,msg:%s",
		len(vi.Sensitives.SensitiveFiles), len(vi.Webshell.HmWebshells), len(vi.Malware.AviraScanResults),
		len(vi.License), len(vi.OriginArtifact), len(vi.SaveFileToKafka), vi.StatusStr, vi.Msg)
	return fmt.Sprintf("%s,%s", s1, s2)
}

// SyncScannedResult used for sync scanned result to all cluster's node
type SyncScannedResult struct {
	Nodes   []NodeInfo              `json:"nodes"`   // 同步结果的目的节点
	Results []ScanResultWithVersion `json:"results"` // 所有已扫描镜像,带扫描版本
}

type ScanResultWithVersion struct {
	Digest                         string                         `json:"digest"`
	SensitiveFileDBVersion         SensitiveFileDBVersion         `json:"sensitiveFileDBVersion"`
	VulnerabilityDBVersion         VulnerabilityDBVersion         `json:"vulnerabilityDBVersion"`
	VulnerabilityScanEngineVersion VulnerabilityScanEngineVersion `json:"vulnerabilityScanEngineVersion"`
	ClamAvDBVersion                ClamAvDBVersion                `json:"clamAvDBVersion"`
	ClamAvEngineVersion            ClamAvEngineVersion            `json:"clamAvEngineVersion"`
	HmEngineVersion                HmEngineVersion                `json:"hmEngineVersion"`
}

type SaveFileToKafka struct {
	Layer    string `json:"layer"`
	FileMd5  string `json:"fileMd5"`
	Data     []byte `json:"data"`
	Filename string `json:"filename"` // 只是用于打日志，文件上传保存的文件名都是使用digest
}

func (vi *SaveFileToKafka) Check() error {
	// 节点镜像暂时不支持
	if vi.Layer == "" {
		return fmt.Errorf("not get layer")
	}
	if vi.FileMd5 == "" {
		return fmt.Errorf("not get file md5")
	}
	if len(vi.Data) == 0 {
		return fmt.Errorf("file is empty")
	}
	return nil
}

func (vi *SaveFileToKafka) LopStr() string {
	s := fmt.Sprintf("filename=%s,layer=%s,fileMd5=%s,data=%d", vi.Filename, vi.Layer, vi.FileMd5, len(vi.Data))
	return s
}
