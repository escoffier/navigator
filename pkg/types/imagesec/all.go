package imagesec

import (
	"fmt"
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
	Size      int64    `json:"size"`      // 镜像大小,byte
	Layers    []Layer  `json:"layers"`    // layer信息,docker 通过history api获取
	ENVS      []string `json:"envs"`      // 镜像的环境变量
	User      string   `json:"user"`      // 镜像的user
	Created   string   `json:"created"`   // RFC 3339 format with nano-seconds.e.g."2022-02-04T21:20:12.497794809Z"
	PullCount int64    `json:"pullCount"` // 镜像的下载次数
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

// ScanSubTask 节点镜像 扫描任务的子任务，即单个镜像
type ScanSubTask struct {
	TaskID         int64         `json:"taskID"`    // 任务id
	SubTaskID      int64         `json:"subTaskID"` // 子任务id,因为任务可以重新调度,所以不能使用 SubTaskID 来确认一次唯一的扫描任务
	ImageFromType  string        `json:"-"`
	NodeInfo       NodeInfo      `json:"nodeInfo"`      // 镜像所属节点，用于校验
	NodeImageMeta  ImageMeta     `json:"nodeImageMeta"` // 节点镜像元数据
	RegImageMeta   ScanImageMeta `json:"regImageMeta"`  // 仓库镜像元数据
	ScanInstance   ScanInstance  `json:"scanInstance"`  // scanInstance
	RegInfo        RegInfo       `json:"regInfo"`
	SensitiveRules []string      `json:"sensitiveRules"` // 扫描所用的敏感文件规则规则（不包含默认敏感文件规则）
	UniqueID       string        `json:"uuid"`           // 生成方式 taskID+SubtaskID+time.Now().UnixMilli()
	ScanTimeout    int64         `json:"scanTimeout"`    // 单位 秒
	DeepScan       bool          `json:"deepScan"`
}

func (vi *ScanSubTask) LogStr() string {
	s := fmt.Sprintf("taskID=%d subtaskID=%d deepScan=%t", vi.TaskID, vi.SubTaskID, vi.DeepScan)
	// 说明是节点镜像
	if vi.NodeInfo.ClusterKey != "" {
		s1 := fmt.Sprintf("clusterKey=%s hostName=%s imageName=%q", vi.NodeInfo.ClusterKey, vi.NodeInfo.HostName, vi.NodeImageMeta.RepoTags)
		s = fmt.Sprintf("%s %s", s, s1)
	}
	// 说明是仓库镜像
	if vi.RegInfo.Username != "" {
		s1 := fmt.Sprintf("regUsername=%s imageName=%s scanInstance=%s",
			vi.RegInfo.Username, vi.RegImageMeta.ImageName(), vi.ScanInstance.ClusterName)
		s = fmt.Sprintf("%s %s", s, s1)
	}

	return s
}

func (vi *ScanSubTask) GenUniqueID() string {
	vi.UniqueID = fmt.Sprintf("%d-%d-%d", vi.TaskID, vi.SubTaskID, time.Now().UnixMilli())
	return vi.UniqueID
}

// VulnResult 软件包和漏洞.参考trivy的结果.注意软件包信息从这里提取,即使没有漏洞
type VulnResult struct {
	Scanned         bool                 `json:"scanned"`
	Target          string               `json:"target"`          // imageName,Java,PHP...
	Class           string               `json:"class"`           // os-pkgs,lang-pkgs
	Type            string               `json:"type"`            // e.g. bundler and pipenv,jar
	Packages        []Package            `json:"packages"`        // 每类的pkgs
	Vulnerabilities VulnerabilityResults `json:"vulnerabilities"` // 漏洞扫描结果
}

// ScanResult 镜像扫描结果.trivy的扫描结果为一个数组，我们会把结果扁平化放到此结构体里。
type ScanResult struct {
	UUID             string                `json:"uuid"`      // 每次扫描任务的唯一标识
	TaskID           int64                 `json:"taskID"`    // 对应的扫描任务id
	SubTaskID        int64                 `json:"subTaskID"` // 对应的子任务id
	ImageUniqueID    uint64                `json:"imageUniqueID"`
	OS               types.OS              `json:"os"`
	VulnResults      []VulnResult          `json:"vulnResults"` // 漏洞和软件包信息
	Sensitives       SensitiveFileResults  `json:"sensitives"`  // 敏感文件
	Malwares         MalwareResults        `json:"malwares"`    // 恶意软件扫描结果
	Webshells        WebshellResults       `json:"webshells"`   // webshell 扫描结果
	License          []License             `json:"license"`     // 镜像使用的license 名
	WebFrameInfo     WebFrameInfo          `json:"webFrameInfo"`
	StatusStr        string                `json:"statusStr"`
	Msg              string                `json:"msg"`
	IgnoreVulnAndPkg bool                  `json:"IgnoreVulnAndPkg"` //  忽略漏洞的数据
	OriginArtifact   ftypes.ArtifactDetail `json:"originArtifact"`   // irene扫描结果中的artifact。scanner利用这里的软件包信息做漏洞匹配.为了方便而设置，和vulnResult相比有冗余数据
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
