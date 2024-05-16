package imagesec

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"gitlab.com/security-rd/go-pkg/logging"
	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

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
	if vi.ImageUniqueID != after.ImageUniqueID || vi.UniqueTarget != after.UniqueTarget ||
		vi.LayerDigest != after.LayerDigest {
		return false
	}
	return true
}

func (vi *VulnToImage) GenUniqueID() uint64 {
	uid := util.GenerateUUID64(fmt.Sprintf("%d-%d-%s", vi.UniqueTarget, vi.ImageUniqueID, vi.LayerDigest))
	vi.UniqueID = uid
	return uid
}

func (vi *VulnToImage) TableName() string {
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
	// class
	var flag uint64
	switch vi.Class {
	case report.ClassOSPkg:
		flag = util.SetBit1(flag, VulnFlagClassOSPkg)
		flag = util.SetBit0(flag, VulnFlagClassLangPkg)
		flag = util.SetBit0(flag, VulnFlagClassConfig)
	case report.ClassLangPkg:
		flag = util.SetBit1(flag, VulnFlagClassLangPkg)
		flag = util.SetBit0(flag, VulnFlagClassOSPkg)
		flag = util.SetBit0(flag, VulnFlagClassConfig)
	case report.ClassConfig:
		flag = util.SetBit1(flag, VulnFlagClassConfig)
		flag = util.SetBit0(flag, VulnFlagClassOSPkg)
		flag = util.SetBit0(flag, VulnFlagClassLangPkg)
	}

	attr := vi.GenCVSSAttr()

	for i := CVSSFlagAVN; i <= CVSSFlagPRH; i++ {
		flag = util.SetBit0(flag, uint64(i))
	}

	for k, v := range attr {
		flag = util.SetBit1(flag, vulnVectorFlag[k][v])
	}
	// can fixed
	if vi.FixedVersion == "" {
		flag = util.SetBit1(flag, VulnFlagNoFixed)
		flag = util.SetBit0(flag, VulnFlagHasFixed)
	}
	if vi.FixedVersion != "" {
		flag = util.SetBit1(flag, VulnFlagHasFixed)
		flag = util.SetBit0(flag, VulnFlagNoFixed)
	}

	// 是否内核
	if (vi.SrcName == "kernel" || vi.SrcName == "linux") && vi.Class == report.ClassOSPkg {
		flag = util.SetBit1(flag, VulnFlagKernel)
		flag = util.SetBit0(flag, VulnFlagNotKernel)
	} else {
		flag = util.SetBit1(flag, VulnFlagNotKernel)
		flag = util.SetBit0(flag, VulnFlagKernel)
	}
	// 特别处理攻击路径
	for i := CVSSFlagAVN; i <= CVSSFlagAVA; i++ {
		flag = util.SetBit0(flag, uint64(i))
	}
	switch strings.ToUpper(vi.AttackPath) {
	case "L":
		flag = util.SetBit1(flag, CVSSFlagAVL)
	case "N":
		flag = util.SetBit1(flag, CVSSFlagAVN)
	case "P":
		flag = util.SetBit1(flag, CVSSFlagAVP)
	case "A":
		flag = util.SetBit1(flag, CVSSFlagAVA)
	case "":
		flag = util.SetBit1(flag, CVSSFlagAVEmpty)
	}

	return flag
}

func (vi *Vuln) Check() error {
	if vi.Name == "" || vi.PkgName == "" {
		return fmt.Errorf("not get name or pkg info")
	}
	// 有些漏洞库的漏洞是没有 cvss 的
	// https://www.debian.org/lts/security/2023/dla-3357-2
	// if len(vi.CVSS) == 0 {
	// 	return fmt.Errorf("not get cvss")
	// }
	return nil
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

func GetSeverityEN(level int64) string {
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

func GetSeverityZH(level int64) string {
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
	OnlineVuln         bool            `gorm:"-" json:"onlineVuln"`
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
	PublishAt          int64           `gorm:"column:publish_at" json:"publishAt"` // 发步时间
	ModifyAt           int64           `gorm:"column:modify_at" json:"modifyAt"`   // 修改时间
	Severity           int64           `gorm:"column:severity" json:"severity"`
	CheckSum           uint64          `gorm:"column:check_sum" json:"checkSum"`
	Language           string          `gorm:"column:language" json:"language"` // 把编程语言入库用于搜索 统一存小写，便于搜索
	Frame              string          `gorm:"column:frame" json:"frame"`       // 开发框架筛选
	FixedVersion       string          `gorm:"column:fixed_version" json:"fixedVersion"`
	Target             string          `gorm:"column:target" json:"target"`
	AttackPath         string          `gorm:"column:attack_path" json:"attackPath"`
	Flag               uint64          `gorm:"column:flag" json:"flag,string"`                          // 把在线镜像的漏洞更新到这里
	CreatedAt          int64           `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt          int64           `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds

	Layer string `gorm:"-" json:"layer"`
}

type VulnToPkg struct {
	ID          int64  `gorm:"primaryKey" json:"id"`
	UniqueID    uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	VulnName    string `gorm:"column:vuln_name" json:"vulnName"`
	PkgUniqueID uint64 `gorm:"column:pkg_unique_id" json:"pkgUniqueID,string"`
	CreatedAt   int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt   int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *VulnToPkg) TableName() string {
	return "ivan_scan_vuln_pkg"
}

func (vi *VulnToPkg) GenUniqueID() uint64 {
	uid := util.GenerateUUID64(fmt.Sprintf("%s-%d", vi.VulnName, vi.PkgUniqueID))
	vi.UniqueID = uid
	return uid
}

func (vi *Vuln) Same(after *Vuln) bool {
	if vi.UniqueID == after.UniqueID && vi.CheckSum == after.CheckSum && vi.Flag == after.Flag && vi.Name == after.Name {
		return true
	}
	return false
}

func (vi *Vuln) GenCheckSum() uint64 {
	createdAt, updatedAt, preCheck, uniqueID := vi.CreatedAt, vi.UpdatedAt, vi.CheckSum, vi.UniqueID
	vi.CreatedAt, vi.UpdatedAt, vi.CheckSum, vi.UniqueID = 0, 0, 0, 0

	bys, err := json.Marshal(vi)
	vi.CreatedAt, vi.UpdatedAt, vi.CheckSum, vi.UniqueID = createdAt, updatedAt, preCheck, uniqueID
	if err != nil {
		return 0
	}
	return util.GenerateUUID64(string(bys))
}

func (vi *Vuln) TableName() string {
	if vi == nil {
		return ""
	}
	if vi.OnlineVuln {
		return "ivan_scan_online_vuln"
	}
	return "ivan_scan_image_vuln"
}

func (vi *Vuln) GenUniqueID() uint64 {
	uid := util.GenerateUUID64(fmt.Sprintf(UniqueVulnFormat, vi.Name, vi.PkgUniqueID))
	vi.UniqueID = uid
	return uid
}

func (vi *Vuln) GenPkgUniqueID(pkgOS types.OS) uint64 {
	key := fmt.Sprintf("%s-%s-%s-%s", vi.PkgName, vi.PkgVersion, pkgOS.Family, pkgOS.Name)
	uid := util.GenerateUUID64(key)
	return uid
}

func (vi *Vuln) GenCVSSAttr() map[string]string {

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

	vi.Language = GetVulnLanguageMap()[vi.PkgType] // 如果没有编程语言，就存空

	if vi.Language == "java" {
		if strings.Contains(vi.PkgName, "struts2") {
			vi.Frame = "struts2"
		}
		if strings.Contains(vi.PkgName, "fastjson") {
			vi.Frame = "fastjson"
		}
	}

	vi.AttackPath = vi.GenAttackPath()
	vi.UniqueID = vi.GenUniqueID()
	vi.Flag = vi.GenFlag()

	vi.CheckSum = vi.GenCheckSum()
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
	if vi.Target != "" && !strings.HasPrefix(vi.Target, "/") {
		vi.Target = "/" + vi.Target
	}

}

func (vi *Vuln) AddLayer(iss []*WebshellToImage) {
	for _, ch := range iss {
		if ch.UniqueTarget == vi.UniqueID {
			vi.Layer = ch.LayerDigest
			break
		}
	}
}

func (vi *VulnView) AddLayer(iss []*WebshellToImage) {
	for _, ch := range iss {
		if ch.UniqueTarget == vi.UniqueID {
			vi.Layer = ch.LayerDigest
			break
		}
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
		Description:        vi.DescriptionEn, // default en,因为 en全一些
		DescriptionZh:      vi.DescriptionZh,
		DescriptionEn:      vi.DescriptionEn,
		References:         vi.References,
		CweIds:             vi.CweIds,
		Title:              vi.Title,
		PublishAt:          vi.PublishAt,
		ModifyAt:           vi.ModifyAt,
		CVSSV2Score:        vi.CVSS[CVSSNvd].V2Score, // 当前需求，默认取NVD的评分
		CVSSV2Vector:       vi.CVSS[CVSSNvd].V2Vector,
		CVSSV3Score:        vi.CVSS[CVSSNvd].V3Score,
		CVSSV3Vector:       vi.CVSS[CVSSNvd].V3Vector,
		SeverityInt:        vi.Severity,
		Severity:           GetSeverityEN(vi.Severity),
		SeverityView:       GetSeverityZH(vi.Severity),
		Flag:               vi.Flag,
		AttackPathView:     vi.GenAttackPathView(),
		AttackPath:         vi.GenAttackPath(),
		Class:              vi.Class,
		ClassView:          vi.GenClassView(),
		KernelVuln:         util.ExistBit1(vi.Flag, VulnFlagKernel),
		Language:           vi.Language,
		Frame:              vi.Frame,
		Layer:              vi.Layer,
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
	if vv.FixedVersion != "" {
		vv.CanFixed = true
	}
	if vv.Target != "" && !strings.HasPrefix(vv.Target, "/") {
		vv.Target = "/" + vv.Target
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
	PkgRelease         string            `json:"pkgRelease"`    // 发行版名字：alpine，redhat等
	Description        string            `json:"description"`   // 描述
	DescriptionEn      string            `json:"descriptionEn"` // 描述:en
	DescriptionZh      string            `json:"descriptionZh"` // 描述:zh
	References         []string          `json:"references"`    // 参考链接
	CweIds             []string          `json:"cweIds"`
	Title              string            `json:"title"`
	CnvdTitle          string            `json:"cnvdTitle"`
	PublishAt          int64             `json:"publishAt"`
	ModifyAt           int64             `json:"modifyAt"`
	CVSSV2Score        float64           `json:"cvssV2Score"`
	CVSSV2Vector       string            `json:"cvssV2Vector"`
	CVSSV3Score        float64           `json:"cvssV3Score"`
	CVSSV3Vector       string            `json:"cvssV3Vector"`
	SeverityInt        int64             `json:"severityInt"`
	Severity           string            `json:"severity"`
	SeverityView       string            `json:"severityView"`
	Flag               uint64            `json:"flag,string"`
	AttackPathView     string            `json:"attackPathView"` // 攻击路径:适配中英文
	AttackPath         string            `json:"attackPath"`     // 攻击路径
	Class              string            `json:"class"`          // 漏洞类型,trivy解析的数据
	ClassView          string            `json:"classView"`      // 漏洞类型
	KernelVuln         bool              `json:"kernelVuln"`     // 是否内核漏洞
	Language           string            `json:"language"`       // 编程语言
	Frame              string            `json:"frame"`          // 开发框架
	FixedVersion       string            `json:"fixedVersion"`
	CanFixed           bool              `json:"canFixed"`
	Target             string            `json:"target"`
	CnnvdFixSuggestion string            `json:"cnnvdFixSuggestion"`
	PosAttr            map[string]string `json:"posAttr"`       // 漏洞详情中雷达图的位置数据
	Attr               map[string]string `json:"attr"`          // 漏洞详情中雷达图的数据,从vector解析出
	AttrValueView      map[string]string `json:"attrValueView"` // 漏洞详情中雷达图的数据,value 适配中英文
	AttrKeyView        map[string]string `json:"attrKeyView"`   // 漏洞详情中雷达图的数据,key 适配中英文
	CreatedAt          int64             `json:"createdAt"`     // milliseconds
	UpdatedAt          int64             `json:"updatedAt"`     // milliseconds
	PolicyDetect       PolicyDetect      `json:"policyDetect"`  // 对各个策略的检测结果
	Layer              string            `json:"layer"`
}

func (vi *VulnView) Simplify() *VulnView {
	vi.References = make([]string, 0)
	return vi
}

func (vi *VulnView) AdaptI18(ctx context.Context) {
	lang := LangZh

	if lan, ok := ctx.Value(AcceptLanguage).(string); ok && lan == LangEn {
		lang = LangEn
	}
	vi.SeverityView = GetSeverityView(lang)[strings.ToUpper(vi.Severity)]
	vi.ClassView = GetVulnClassView(lang)[vi.Class]
	vi.AttrKeyView = GetVulnCvssAttrKeyView(lang)
	vi.AttrValueView = GenVulnCVSSV3AttrView(vi.Attr, lang)
	vi.AttackPathView = vi.AttrValueView[VulnCvssKeyAV]

	if lang == LangZh && vi.DescriptionZh != "" {
		vi.Description = vi.DescriptionZh
	}

	if lang == LangZh && vi.CnvdTitle != "" {
		vi.Title = vi.CnvdTitle
	}
	if lang == LangEn && vi.DescriptionEn != "" {
		vi.Description = vi.DescriptionEn
	}
}

type VulnOverview struct {
	VulnTotal int64         `json:"vulnTotal"`
	Severity  SeverityCount `json:"severity"`
}

type SeverityCount struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	Unknown  int64 `json:"unknown"`
}

type VulnOverviewParam struct {
	OnlineImage string
}

type VulnViews []*VulnView

func (vl VulnViews) Len() int {
	return len(vl)
}

func (vl VulnViews) Less(i, j int) bool {
	return vl[i].SeverityInt >= vl[j].SeverityInt
}

func (vl VulnViews) Swap(i, j int) {
	vl[i], vl[j] = vl[j], vl[i]
}
