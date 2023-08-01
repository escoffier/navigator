package types

import (
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 单个镜像的扫描报告
type ImageRiskOverView struct {
	ImageID           int64                   `json:"imageID"`
	ImageName         string                  `json:"imageName"`
	Suggests          []imagesec.ImageSuggest `json:"suggests"`
	VulnSeverityCount VulnSeverityCount       `json:"vulnSeverityCount"` // 漏洞层级分布
}

type ImageResponse struct {
	Images  []Image `json:"images"`
	End     bool    `json:"end"`
	StartID int64   `json:"startID"`
}

type VirusInfo struct {
	FilePath  string   `json:"filePath"`
	VirusName string   `json:"virusName"`
	Images    []string `json:"images"`
}

// 镜像列表
type Image struct {
	ImageID       int64             `json:"imageID"`
	ImageName     string            `json:"imageName"`
	FixedVuln     VulnSeverityCount `json:"fixedVuln"`
	UnFixedVuln   VulnSeverityCount `json:"unFixedVuln"`
	Malicious     int64             `json:"malicious"` // 病毒
	RiskScore     int64             `json:"riskScore"`
	NotMaintained bool              `json:"notMaintained"` // 镜像不再维护
	Flag          uint64            `json:"flag"`
}

func (im *Image) AddVulnSeverityCount(vulns []*imagesec.VulnView) {

	for i := range vulns {

		if vulns[i].FixedVersion != "" {

			switch vulns[i].SeverityInt {
			case model.SeverityCriticalInt:
				im.FixedVuln.Critical++
			case model.SeverityHighInt:
				im.FixedVuln.High++
			case model.SeverityMediumInt:
				im.FixedVuln.Medium++
			case model.SeverityLowInt:
				im.FixedVuln.Low++
			case model.SeverityUnknownInt:
				im.FixedVuln.Unknown++
			}
		}

		if vulns[i].FixedVersion == "" {

			switch vulns[i].SeverityInt {
			case model.SeverityCriticalInt:
				im.UnFixedVuln.Critical++
			case model.SeverityHighInt:
				im.UnFixedVuln.High++
			case model.SeverityMediumInt:
				im.UnFixedVuln.Medium++
			case model.SeverityLowInt:
				im.UnFixedVuln.Low++
			case model.SeverityUnknownInt:
				im.UnFixedVuln.Unknown++
			}
		}
	}
}

type VulnSeverityGroup struct {
	Severity string           `json:"severity"` // 威胁等级
	Vulns    []*VulnWithImage `json:"vulns"`
}

type VulnWithImageResponse struct {
	Vulns   []VulnWithImage `json:"vulns"`
	End     bool            `json:"end"`
	ImageID int64           `json:"imageID"`
	StartID int64           `json:"startID"`
}

// 漏洞及影响镜像
type VulnWithImage struct {
	Images     []string   `json:"images"`
	VulnDetail VulnDetail `json:"vulnDetail"`
	UniqueVuln uint64     `json:"-"`
}

// 漏洞详情
type VulnDetail struct {
	Name          string  `json:"name"`          // 形如CVE-2021-28831
	Severity      string  `json:"severity"`      // 威胁等级
	SeverityInt   int64   `json:"-"`             // 威胁等级
	FixedBy       string  `json:"fixedby"`       // 修复版本
	Description   string  `json:"description"`   // 漏洞介绍
	Cvssv3score   float64 `json:"cvssv3Score"`   // 漏洞评分
	Cvssv3vector  string  `json:"cvssv3Vector"`  // 攻击维度
	CnvdTitle     string  `json:"cnvdTitle"`     // 漏洞类型 // 取值方式:vuln.Metadata.CNVDs[0].Title
	CNNVDNumber   string  `json:"CNNVDNumber"`   //  CNNVD编号
	FixSuggestion string  `json:"fixSuggestion"` // 修复建议
	PkgName       string  `json:"pkgName"`       // 软件包来源
	PkgVersion    string  `json:"pkgVersion"`    // 软件包版本
	UniqueVuln    uint64  `json:"uniqueVuln,string"`
	Link          string  `json:"link"`     // 链接
	Class         string  `json:"class"`    // 漏洞类型:os-pkgs:表示系统漏洞， lang-pkgs 表示应用漏洞
	IsKernel      bool    `json:"isKernel"` // 是否是内核漏洞
}

// 漏洞详情按层级统计
type VulnDetailSeverityGroup struct {
	Critical []VulnWithImage `json:"critical"`
	High     []VulnWithImage `json:"high"`
	Medium   []VulnWithImage `json:"medium"`
	Low      []VulnWithImage `json:"low"`
	Unknown  []VulnWithImage `json:"unknown"`
}

func ModelToVulnDetail(vuln *imagesec.VulnView) VulnDetail {
	if vuln == nil {
		return VulnDetail{}
	}
	vd := VulnDetail{
		Name:          vuln.Name,
		Severity:      imagesec.GetSeverityEN(vuln.SeverityInt),
		SeverityInt:   vuln.SeverityInt,
		FixedBy:       vuln.FixedVersion,
		Description:   vuln.Description,
		Cvssv3score:   vuln.CVSSV3Score,
		Cvssv3vector:  vuln.CVSSV3Vector,
		CnvdTitle:     vuln.Title,
		CNNVDNumber:   vuln.CnnvdName,
		FixSuggestion: vuln.FixedVersion,
		PkgName:       vuln.PkgName,
		PkgVersion:    vuln.PkgVersion,
		UniqueVuln:    vuln.UniqueID,
		Class:         vuln.Class,
		IsKernel:      util.ExistBit1(vuln.Flag, model.VulnFlagKernel),
	}
	if len(vuln.References) > 0 {
		vd.Link = vuln.References[0]
	}
	if vd.FixedBy == "" {
		vd.FixSuggestion = ""
	}

	return vd
}

// 漏洞个数按层级统计
type VulnSeverityCount struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	Unknown  int64 `json:"unknown"`
}

// 镜像安全问题统计
type ImageSecurity struct {
	HasVuln          int64 `json:"hasVuln"`
	HasMalicious     int64 `json:"hasMalicious"`
	HasSensitive     int64 `json:"hasSensitive"`
	HasWebshell      int64 `json:"hasWebshell"`
	HasSoftware      int64 `json:"hasSoftware"`
	HasExceptEnv     int64 `json:"hasExceptEnv"`
	ExceptionBoot    int64 `json:"exceptionBoot"`
	HasExceptLicense int64 `json:"hasExceptLicense"`
}

// 风险信息总揽
type RiskOverView struct {
	ImageCount             int64             `json:"imageCount"`
	OnlineImageCount       int64             `json:"onlineImageCount"`
	TrustedImageCount      int64             `json:"trustedImageCount"`
	HasFixedVulnImageCount int64             `json:"hasFixedVulnImageCount"`
	ReinforcedImageCount   int64             `json:"reinforcedImageCount"`
	VulnSum                int64             `json:"vulnSum"` // 漏洞总数
	VulnSeverity           VulnSeverityCount `json:"vulnSeverity"`
	ImageSecurity          ImageSecurity     `json:"imageSecurity"`
}

func (rov *RiskOverView) Serializer() {
	rov.VulnSum = rov.VulnSeverity.Unknown + rov.VulnSeverity.Low +
		rov.VulnSeverity.Medium + rov.VulnSeverity.High + rov.VulnSeverity.Critical
}

func (rov *RiskOverView) StatisticsImageAttr(images []*imagesec.ImageBaseResponse) {

	for i := range images {
		rov.ImageCount++
		if images[i].Online {
			rov.OnlineImageCount++
		}

		securityIssue := images[i].SecurityIssue
		for j := range securityIssue {
			switch securityIssue[j].Value {
			case imagesec.ExceptionVuln:
				rov.ImageSecurity.HasVuln++
			case imagesec.ExceptionMalware:
				rov.ImageSecurity.HasMalicious++
			case imagesec.ExceptionSensitive:
				rov.ImageSecurity.HasSensitive++
			case imagesec.ExceptionWebshell:
				rov.ImageSecurity.HasWebshell++
			case imagesec.ExceptionPKG:
				rov.ImageSecurity.HasSoftware++
			case imagesec.ExceptionEnv:
				rov.ImageSecurity.HasExceptEnv++
			case imagesec.ExceptionBoot:
				rov.ImageSecurity.ExceptionBoot++
			case imagesec.ExceptionPkgLicense:
				rov.ImageSecurity.HasExceptLicense++
			case imagesec.TrustedString:
				rov.TrustedImageCount++
			case imagesec.HasFixedVulnString:
				rov.HasFixedVulnImageCount++
			}
		}
	}
}

func (rov *RiskOverView) StatisticsVulnSeverity(vuln model.ExportVulnImage) {
	switch vuln.Severity {
	case model.SeverityCriticalInt:
		rov.VulnSeverity.Critical++
	case model.SeverityHighInt:
		rov.VulnSeverity.High++
	case model.SeverityMediumInt:
		rov.VulnSeverity.Medium++
	case model.SeverityLowInt:
		rov.VulnSeverity.Low++
	case model.SeverityUnknownInt:
		rov.VulnSeverity.Unknown++
	}
}

func StatisticsVulnSeverity(vulns []*imagesec.VulnView) VulnSeverityCount {
	res := VulnSeverityCount{}

	for i := range vulns {
		switch vulns[i].SeverityInt {
		case model.SeverityCriticalInt:
			res.Critical++
		case model.SeverityHighInt:
			res.High++
		case model.SeverityMediumInt:
			res.Medium++
		case model.SeverityLowInt:
			res.Low++
		case model.SeverityUnknownInt:
			res.Unknown++
		}
	}
	return res
}

type ImageIDName struct {
	ImageID   int64  `json:"imageID"`
	ImageName string `json:"imageName"`
}

type ImageIDNameWithTask struct {
	TaskId int64         `json:"taskId"`
	Images []ImageIDName `json:"images"`
}

type KoaResponse struct {
	Data KoaDataResponse `json:"data"`
	Msg  string          `json:"msg"`  // 如果出错，这里暂时错误信息
	Code int64           `json:"code"` // 200表示正常，500表示出错
}

type KoaDataResponse struct {
	Status    string      `json:"status"` // inprogress，success，failed
	FilePath  string      `json:"filePath"`
	FailedMsg []FailedMsg `json:"failedMsg"`
}

type FailedMsg struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
	Url     string `json:"url"`
}
