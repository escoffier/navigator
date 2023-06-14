package imagesec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gitlab.com/security-rd/go-pkg/logging"
	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 漏洞关联镜像表
type VulnToImage struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	UniqueID      uint64 `gorm:"column:unique_id" json:"uniqueID,string"`         // 数据库的中唯一建，去重效率高
	UniqueTarget  uint64 `gorm:"column:unique_target" json:"uniqueTarget,string"` // 漏洞的唯一标识
	ImageUniqueID uint64 `gorm:"column:image_unique_id" json:"imageUniqueID,string"`
	LayerDigest   string `gorm:"column:layer_digest" json:"layerDigest"`
	CreatedAt     int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *VulnToImage) Same(after *VulnToImage) bool {
	if vi.ImageUniqueID != after.ImageUniqueID || vi.UniqueTarget != after.UniqueTarget || vi.LayerDigest != after.LayerDigest {
		return false
	}
	return true
}

func (vi *VulnToImage) GenUniqueID() uint64 {
	return util.GenerateUUID64(fmt.Sprintf("%d-%d-%s", vi.UniqueTarget, vi.ImageUniqueID, vi.LayerDigest))
}

func (vi *VulnToImage) TableName() string {
	// 由于仓库镜像，节点镜像，CI镜像的数据结构一致，但是数据量较大，所以要做分表处理
	if vi == nil {
		return ""
	}
	return "ivan_image_vuln_issue"
}

func (vi *Vuln) GenClassView() string {
	switch vi.Class {
	case report.ClassLangPkg:
		return VulnsClassPkgVuln
	case report.ClassOSPkg:
		return VulnClassOSVuln
	case report.ClassConfig:
		return VulnsClassConfigVuln
	}
	return ""
}

func (vi *Vuln) GenKernelVuln() bool {
	kernelVuln := os.Getenv("IDENTITY_KERNEL_VULN")
	// 提供开关临时关闭内核漏洞的判断
	if kernelVuln == model.FalseString {
		return false
	}
	if util.ExistBit1(vi.Flag, VulnFlagKernelPkg) {
		return true
	}
	return false
}

func (vi *Vuln) GenAttackPathView() string {
	attr := vi.GenCVSSAttr()
	return vulnVectorAttrWithZHView["AV"][attr["AV"]]
}

func (vi *Vuln) GenAttackPath() string {
	av := vi.GenCVSSAttr()["AV"]
	if av == "" {
		av = "A"
	}
	return av
}

func (vi *Vuln) GenFlag() uint64 {

	vi.Deserialize()
	// class
	var flag uint64
	switch vi.Class {
	case report.ClassOSPkg:
		flag = util.SetBit1(flag, VulnFlagClassOSPkg)
	case report.ClassLangPkg:
		flag = util.SetBit1(flag, VulnFlagClassLangPkg)
	case report.ClassConfig:
		flag = util.SetBit1(flag, VulnFlagClassConfig)
	}

	attr := vi.GenCVSSAttr()
	for k, v := range attr {
		flag = util.SetBit1(flag, vulnVectorFlag[k][v])
	}
	// can fixed
	if vi.FixedVersion == "" {
		flag = util.SetBit1(flag, VulnFlagNoFixed)
	}
	if vi.FixedVersion != "" {
		flag = util.SetBit1(flag, VulnFlagHasFixed)
	}

	// 是否内核
	if vi.SrcName == "kernel" || vi.SrcName == "linux" {
		flag = util.SetBit1(flag, VulnFlagKernelPkg)
	} else {
		flag = util.SetBit1(flag, VulnFlagAppPkg)
	}
	return flag
}

func GetVulnLanguageMap() map[string]string {
	return languageMap
}

func GetSeverityInt(level string) int64 {
	switch strings.ToUpper(level) {
	case SeverityCritical:
		return SeverityCriticalInt
	case SeverityHigh:
		return SeverityHighInt
	case SeverityMedium:
		return SeverityMediumInt
	case SeverityLow:
		return SeverityLowInt
	case SeverityUnknown:
		return SeverityUnknownInt
	}
	return 0
}

func GetSeverity(level int64) string {
	switch level {
	case SeverityCriticalInt:
		return SeverityCritical
	case SeverityHighInt:
		return SeverityHigh
	case SeverityMediumInt:
		return SeverityMedium
	case SeverityLowInt:
		return SeverityLow
	case SeverityUnknownInt:
		return SeverityUnknown
	default:
		return ""
	}
}

func GetSeverityView(level int64) string {
	switch level {
	case SeverityCriticalInt:
		return SeverityCriticalView
	case SeverityHighInt:
		return SeverityHighView
	case SeverityMediumInt:
		return SeverityMediumView
	case SeverityLowInt:
		return SeverityLowView
	default:
		return SeverityUnknownView
	}
}

// 漏洞表
type Vuln struct {
	ID                 int64           `gorm:"primaryKey" json:"id"`
	UniqueID           uint64          `gorm:"column:unique_id" json:"uniqueID,string"`
	PkgUniqueID        uint64          `gorm:"column:pkg_unique_id" json:"pkgUniqueID,string"`
	Name               string          `gorm:"column:name" json:"name"`               // 形如CVE-2021-28831
	PkgName            string          `gorm:"column:pkg_name" json:"pkg_name"`       // 软件包来源
	SrcName            string          `gorm:"column:src_name" json:"srcName"`        // 软件包上游来源，可用于判断是内核漏洞还是系统漏洞
	PkgVersion         string          `gorm:"column:pkg_version" json:"pkg_version"` // 软件包版本
	CnnvdName          string          `gorm:"column:cnnvd_name" json:"cnnvdName"`
	CnnvdFixSuggestion string          `gorm:"column:cnnvd_fix_suggestion" json:"cnnvd_fix_suggestion"`
	PkgType            string          `gorm:"column:pkg_type" json:"pkgType"`             // 发行版名字：alpine，redhat,对应原 vuln 表中的 namespace  trivy 结构中的Type
	DescriptionEn      string          `gorm:"column:description_en" json:"descriptionEn"` // 描述
	DescriptionZh      string          `gorm:"column:description_zh" json:"descriptionZh"` // 描述
	References         []string        `gorm:"-" json:"references"`                        // 参考链接
	ReferencesJSON     string          `gorm:"column:references" json:"-"`
	Class              string          `gorm:"class" json:"class"` // 漏洞类型
	CVSSJSON           string          `gorm:"column:cvss" json:"-"`
	CVSS               map[string]Cvss `gorm:"-" json:"cvss"`
	CweIds             []string        `gorm:"-" json:"cweIds"`
	CweIdsJSON         string          `gorm:"column:ced_ids" json:"-"`
	Title              string          `gorm:"column:title" json:"title"` // 漏洞库的取的 title 英文
	CnvdTitle          string          `gorm:"column:cnvd_title" json:"cnvdTitle"`
	PublishDate        int64           `gorm:"column:publish_date" json:"publishDate"`
	ModificationData   int64           `gorm:"column:modification_data" json:"modificationData"`
	Severity           int64           `gorm:"column:severity" json:"severity"`
	CheckSum           uint64          `gorm:"column:check_sum" json:"checkSum"`
	Language           string          `gorm:"column:language" json:"language"` // 把编程语言入库用于搜索 统一存小写，便于搜索
	Frame              string          `gorm:"column:frame" json:"frame"`       // 开发框架筛选
	FixedVersion       string          `gorm:"column:fixed_version" json:"fixedVersion"`
	Target             string          `gorm:"column:target" json:"target"`
	Flag               uint64          `gorm:"column:flag" json:"flag,string"`

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *Vuln) Same(after *Vuln) bool {
	vi.CheckSum = vi.GenCheckSum()
	after.CheckSum = after.GenCheckSum()
	return vi.CheckSum == after.CheckSum
}

func (vi *Vuln) GenCheckSum() uint64 {
	createdAt, updatedAt, preCheck := vi.CreatedAt, vi.UpdatedAt, vi.CheckSum
	vi.CreatedAt, vi.UpdatedAt, vi.CheckSum = 0, 0, 0
	bys, err := json.Marshal(vi)
	vi.CreatedAt, vi.UpdatedAt, vi.CheckSum = createdAt, updatedAt, preCheck
	if err != nil {
		return 0
	}
	return util.GenerateUUID64(string(bys))
}

func (vi *Vuln) TableName() string {
	return "ivan_scan_image_vuln"
}

func (vi *Vuln) GenUniqueID() uint64 {
	return util.GenerateUUID64(fmt.Sprintf(UniqueVulnFormat, vi.Name, vi.PkgUniqueID))
}

func (vi *Vuln) GenPkgUniqueID(pkgOS types.OS) uint64 {
	key := fmt.Sprintf(UniquePkgFormat, vi.PkgName, vi.PkgVersion, pkgOS.Family, pkgOS.Name)
	uid := util.GenerateUUID64(key)
	return uid
}

func (vi *Vuln) GenCVSSAttr() map[string]string {
	vi.Deserialize()

	nvd := vi.CVSS[CVSSNvd]
	if nvd.V3Vector != "" {
		return genCVSSv3Vector(nvd.V3Vector)
	} else if nvd.V2Vector != "" {
		return genCVSSv2Vector(nvd.V2Vector)
	}
	return GetDefaultAttr()
}

func (vi *Vuln) GenPosAttr() map[string]string {
	vi.Deserialize()

	attr := vi.GenCVSSAttr()
	pos := make(map[string]string)
	for k, v := range attr {
		pos[k] = vulnPosAttr[k][v]
	}
	return pos
}

func (vi *Vuln) Serialize() {
	if len(vi.CVSS) > 0 {
		bys, err := json.Marshal(vi.CVSS)
		if err != nil {
			logging.Get().Err(err).Msg("Vuln.Serialize")
		} else {
			vi.CVSSJSON = string(bys)
		}
	}

	if len(vi.References) > 0 {
		bys, err := json.Marshal(vi.References)
		if err != nil {
			logging.Get().Err(err).Msg("Vuln.Serialize")
		} else {
			vi.ReferencesJSON = string(bys)
		}
	}

	if len(vi.CweIds) > 0 {
		bys, err := json.Marshal(vi.CweIds)
		if err != nil {
			logging.Get().Err(err).Msg("Vuln.Serialize")
		} else {
			vi.CweIdsJSON = string(bys)
		}
	}
	vi.Flag = vi.GenFlag()

	vi.Language = GetVulnLanguageMap()[vi.PkgType] // 如果没有编程语言，就存空

	if vi.Language == "java" {
		if strings.Contains(vi.PkgName, "struts2") {
			vi.Frame = "struts2"
		}
		if strings.Contains(vi.PkgName, "fastjson") {
			vi.Frame = "fastjson"
		}
	}

}

func (vi *Vuln) Deserialize() {
	if vi.CVSSJSON != "" {
		cvss := make(map[string]Cvss)
		if err := json.Unmarshal([]byte(vi.CVSSJSON), &cvss); err != nil {
			logging.Get().Err(err).Msg("Vuln.Deserialize")
			cvss = make(map[string]Cvss) // 一定改成默认值
		}
		vi.CVSS = cvss
	}

	if vi.ReferencesJSON != "" {
		references := make([]string, 0)
		if err := json.Unmarshal([]byte(vi.ReferencesJSON), &references); err != nil {
			logging.Get().Err(err).Msg("Vuln.Deserialize")
			references = make([]string, 0)
		}
		vi.References = references
	}
	if vi.CweIdsJSON != "" {
		cweIds := make([]string, 0)
		if err := json.Unmarshal([]byte(vi.CweIdsJSON), &cweIds); err != nil {
			logging.Get().Err(err).Msg("Vuln.Deserialize")
			cweIds = make([]string, 0)
		}
		vi.CweIds = cweIds
	}
}

func (vi *Vuln) GenVulnView() *VulnView {

	vi.Deserialize()

	vv := VulnView{
		ID:                 vi.ID,
		UniqueID:           vi.UniqueID,
		PkgUniqueID:        vi.PkgUniqueID,
		Name:               vi.Name,
		PkgName:            vi.PkgName,
		PkgVersion:         vi.PkgVersion,
		CnnvdName:          vi.CnnvdName,
		PkgRelease:         vi.PkgType,
		Description:        vi.DescriptionZh, // default zh
		DescriptionZh:      vi.DescriptionZh,
		DescriptionEn:      vi.DescriptionEn,
		References:         vi.References,
		CweIds:             vi.CweIds,
		Title:              vi.Title,
		PublishDate:        vi.PublishDate,
		ModificationData:   vi.ModificationData,
		CVSSV2Score:        vi.CVSS[CVSSNvd].V2Score, // 当前需求，默认取NVD的评分
		CVSSV2Vector:       vi.CVSS[CVSSNvd].V2Vector,
		CVSSV3Score:        vi.CVSS[CVSSNvd].V3Score,
		CVSSV3Vector:       vi.CVSS[CVSSNvd].V3Vector,
		SeverityInt:        vi.Severity,
		Severity:           GetSeverity(vi.Severity),
		SeverityView:       GetSeverityView(vi.Severity),
		Flag:               vi.Flag,
		AttackPathView:     vi.GenAttackPathView(),
		AttackPath:         vi.GenAttackPath(),
		Class:              vi.Class,
		ClassView:          vi.GenClassView(),
		KernelVuln:         vi.GenKernelVuln(),
		Language:           vi.Language,
		Frame:              vi.Frame,
		FixedVersion:       vi.FixedVersion,
		Target:             vi.Target,
		CnnvdFixSuggestion: vi.CnnvdFixSuggestion,
		PosAttr:            vi.GenPosAttr(),
		CreatedAt:          vi.CreatedAt,
		UpdatedAt:          vi.UpdatedAt,
		Attr:               vi.GenCVSSAttr(),
	}
	vv.PosAttr = vi.GenPosAttr()

	if len(vv.References) == 0 {
		vv.References = make([]string, 0)
	}
	if len(vv.CweIds) == 0 {
		vv.CweIds = make([]string, 0)
	}
	if vv.FixedVersion == "" {
		vv.CnnvdFixSuggestion = ""
	}
	if vv.Description == "" {
		vv.Description = vi.DescriptionEn
	}

	return &vv
}

type Cvss struct {
	V2Score  float64 `json:"V2Score"`
	V2Vector string  `json:"V2Vector"`
	V3Score  float64 `json:"V3Score"`
	V3Vector string  `json:"V3Vector"`
}

// 整合漏洞数据(返回给前端的数据结构)
type VulnView struct {
	ID                 int64             `json:"id"`
	UniqueID           uint64            `json:"uniqueID,string"`
	PkgUniqueID        uint64            `json:"pkgUniqueID,string"`
	Name               string            `json:"name"` // 形如CVE-2021-28831
	PkgName            string            `json:"pkgName"`
	PkgVersion         string            `json:"pkgVersion"`
	CnnvdName          string            `json:"cnnvdName"`
	PkgRelease         string            `json:"pkgRelease"`  // 发行版名字：alpine，redhat等
	Description        string            `json:"description"` // 描述
	DescriptionEn      string            `json:"-"`           // 描述
	DescriptionZh      string            `json:"-"`           // 描述
	References         []string          `json:"references"`  // 参考链接
	CweIds             []string          `json:"cweIds"`
	Title              string            `json:"title"`
	PublishDate        int64             `json:"publishDate"`
	ModificationData   int64             `json:"modificationData"`
	CVSSV2Score        float64           `json:"cvssV2Score"`
	CVSSV2Vector       string            `json:"cvssV2Vector"`
	CVSSV3Score        float64           `json:"cvssV3Score"`
	CVSSV3Vector       string            `json:"cvssV3Vector"`
	SeverityInt        int64             `json:"severityInt"`
	Severity           string            `json:"severity"`
	SeverityView       string            `json:"severityView"` // 给前端
	Flag               uint64            `json:"flag,string"`
	AttackPathView     string            `json:"attackPathView"` // 攻击路径
	AttackPath         string            `json:"attackPath"`     // 攻击路径
	Class              string            `json:"class"`          // 漏洞类型,trivy解析的数据
	ClassView          string            `json:"classView"`      // 漏洞类型:文案
	KernelVuln         bool              `json:"kernelVuln"`     // 是否内核漏洞
	Language           string            `json:"language"`       // 编程语言
	Frame              string            `json:"frame"`          // 开发框架
	FixedVersion       string            `json:"fixedVersion"`
	Target             string            `json:"target"`
	CnnvdFixSuggestion string            `json:"cnnvdFixSuggestion"`
	PosAttr            map[string]string `json:"posAttr"` // 漏洞详情中雷达图的位置数据
	Attr               map[string]string `json:"attr"`    // 漏洞详情中雷达图的数据,从vector解析出

	CreatedAt int64 `json:"createdAt"` // milliseconds
	UpdatedAt int64 `json:"updatedAt"` // milliseconds

	PolicyDetect PolicyDetect `json:"policyDetect"` // 对各个策略的检测结果
}

func (vi *VulnView) AdaptI18(ctx context.Context) {
	lang, ok := ctx.Value(AcceptLanguage).(string)
	if ok && lang == model.LangEn {
		vi.Description = vi.DescriptionEn
	}
}
