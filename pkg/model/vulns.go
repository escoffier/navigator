package model

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	LanguageMap = map[string]string{
		"bundler":      "ruby",
		"pipenv":       "python",
		"gemfile":      "ruby",
		"pipfile":      "python",
		"poetry":       "python",
		"composer":     "php",
		"package-lock": "node.js",
		"yarn":         "node.js",
		"jar":          "java",
		"war":          "ava",
		"ear":          "java",
		"gobinary":     "go",
		"gemspec":      "ruby",
		"node-pkg":     "node.js",
		"npm":          "node.js",
		"python-pkg":   "python",
		"cargo":        "rust",
		"pom":          "java",
		"nuget":        ".net",
		"pip":          "python",
		"gomod":        "go",
	}
)

func GetVulnLanguageMap() map[string]string {
	return LanguageMap
}

func GetSeverityInt(level string) int {
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
	default:
		return SeverityNegligibleInt
	}
}

const (
	SeverityCriticalInt   = 5
	SeverityHighInt       = 4
	SeverityMediumInt     = 3
	SeverityLowInt        = 2
	SeverityUnknownInt    = 1
	SeverityNegligibleInt = 0
	SeverityCritical      = "CRITICAL"
	SeverityHigh          = "HIGH"
	SeverityMedium        = "MEDIUM"
	SeverityLow           = "LOW"
	SeverityNegligible    = "NEGLIGIBLE"
	SeverityUnknown       = "UNKNOWN"

	SeverityCriticalView   = "严重"
	SeverityHighView       = "高"
	SeverityMediumView     = "中"
	SeverityLowView        = "低"
	SeverityNegligibleView = "可忽略"
	SeverityUnknownView    = "未知"
)

const (
	VulnFlagKernel       = 0 // 内核漏洞
	VulnFlagClassOSPkg   = 1 // 系统漏洞
	VulnFlagClassLangPkg = 2 // 应用漏洞
	VulnFlagClassConfig  = 3 // 配置文件
	VulnFlagHasFixed     = 4 // 可修复
)

func GetSeverity(level int) string {
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
	case SeverityNegligibleInt:
		return SeverityNegligible
	default:
		return ""
	}
}

func GetSeverityView(level int) string {
	switch level {
	case SeverityCriticalInt:
		return SeverityCriticalView
	case SeverityHighInt:
		return SeverityHighView
	case SeverityMediumInt:
		return SeverityMediumView
	case SeverityLowInt:
		return SeverityLowView
	case SeverityUnknownInt:
		return SeverityUnknownView
	default:
		return SeverityNegligibleView
	}
}

func (vu *Vuln) DefaultOmitField() []string {
	return []string{"description", "metadata_json", "extra_info", "link_json"}
}

var vulnAttr map[string]map[string]string
var vulnPosAttr map[string]map[string]string

var defaultAttr map[string]string

func init() {
	var once sync.Once
	once.Do(func() {
		vulnAttr = make(map[string]map[string]string)
		// 攻击位置难易
		vulnAttr["AV"] = map[string]string{
			"N": "网络访问",
			"L": "本地访问",
			"P": "物理访问",
			"":  "相邻网络访问",
			"A": "相邻网络访问", // https://www.first.org/cvss/calculator/3.1
		}
		// 是否自动化触发
		vulnAttr["UI"] = map[string]string{
			"N": "自动",
			"R": "非自动",
		}
		// 所需权限级别 and 攻击复杂度
		vulnAttr["AC"] = map[string]string{
			"N": "无",
			"L": "低",
			"H": "高",
		}
		// 信息泄露风险
		vulnAttr["C"] = map[string]string{
			"N": "无",
			"L": "低",
			"H": "高",
		}
		// 信息/系统篡改风险
		vulnAttr["A"] = map[string]string{
			"N": "无",
			"L": "低",
			"H": "高",
		}
		//  权限范围扩大
		vulnAttr["S"] = map[string]string{
			"C": "扩大",
			"U": "不变",
		}
		// 造成 DoS 风险
		vulnAttr["PR"] = map[string]string{
			"N": "无",
			"L": "低",
			"H": "高",
		}

		defaultAttr = map[string]string{
			"AV": "相邻网络访问", // 攻击位置难易
			"UI": "非自动",    // 是否自动化触发
			"AC": "无",      // 所需权限级别, 攻击复杂度 都是这个字段
			"C":  "无",      // 信息泄露风险
			"A":  "无",      // 信息/系统篡改风险
			"PR": "无",      // 造成 DoS 风险
			"S":  "不变",     // 权限范围扩大
		}

		vulnPosAttr = make(map[string]map[string]string, 0)
		// 攻击位置难易
		vulnPosAttr["AV"] = map[string]string{
			"N": "100%",
			"A": "75%",
			"L": "50%",
			"P": "25%",
		}
		// 是否自动化触发
		vulnPosAttr["UI"] = map[string]string{
			"N": "100%",
			"R": "0%",
		}
		// 攻击复杂度
		vulnPosAttr["AC"] = map[string]string{
			"L": "100%",
			"H": "50%",
		}
		// 信息泄露风险
		vulnPosAttr["C"] = map[string]string{
			"N": "0%",
			"L": "50%",
			"H": "100%",
		}
		// 信息/系统篡改风险
		vulnPosAttr["A"] = map[string]string{
			"N": "0%",
			"L": "50%",
			"H": "100%",
		}
		//  权限范围扩大
		vulnPosAttr["S"] = map[string]string{
			"C": "100%",
			"U": "0%",
		}
		// 所需权限级别
		vulnPosAttr["PR"] = map[string]string{
			"N": "100%",
			"L": "67%",
			"H": "33%",
		}
		// 触发dos风险
		vulnPosAttr["I"] = map[string]string{
			"N": "0%",
			"L": "50%",
			"H": "100%",
		}

	})
}

func (*Vuln) TableName() string {
	return "ivan_scanner_vulns"
}

func (vu *Vuln) SetDefaultAttr() {
	if vu.Attr == nil {
		vu.Attr = make(map[string]string)
	}
	if vu.CvssMap == nil {
		vu.CvssMap = make(map[string]string)
	}
	for k, v := range defaultAttr {
		vu.Attr[k] = v
	}
}

func (vu *Vuln) Serialize() {
	if vu.Metadata != nil {
		sort.Sort(CnvdMetadatas(vu.Metadata.CNVDs))
		bys, err := json.Marshal(vu.Metadata)
		if err != nil {
			logging.Get().Err(err).Msg("Vuln.Serialize")
		} else {
			vu.MetadataJSON = bys
		}
	}
	if len(vu.Link) > 0 {
		sort.Strings(vu.Link)
		bys, err := json.Marshal(vu.Link)
		if err != nil {
			logging.Get().Err(err).Msg("Vuln.Serialize")
		} else {
			vu.LinkJSON = bys
		}
	}
	if vu.Language == "" {
		vu.Language = GetVulnLanguageMap()[vu.Namespace] // 如果没有编程语言，就存空
	}

	if vu.Language == "java" {
		if strings.Contains(vu.PkgName, "struts2") {
			vu.Frame = "struts2"
		}
		if strings.Contains(vu.PkgName, "fastjson") {
			vu.Frame = "fastjson"
		}
	}

}

func (vu *Vuln) Deserialize() {
	if len(vu.MetadataJSON) > 0 {
		meta := VulnMatedata{}
		if err := json.Unmarshal(vu.MetadataJSON, &meta); err != nil {
			logging.Get().Err(err).Msg("Vuln.Deserialize")
			meta = VulnMatedata{} // 一定改成默认值
		}
		vu.Metadata = &meta
	}

	if len(vu.LinkJSON) > 0 {
		link := make([]string, 0)
		if err := json.Unmarshal(vu.LinkJSON, &link); err != nil {
			logging.Get().Err(err).Msg("Vuln.Deserialize")
			link = make([]string, 0)
		}
		vu.Link = link
	}

	vu.SetDefaultAttr() // 先设置成默认值，接下来更新

	// 格式化攻击路径
	// 对于class是os-pkgs: 0.0.0.0:5566/zaherg/php-cli-xdebug:7.2 (alpine 3.10.2)
	// 对于calss是lang-pkgs：root/.local/share/helm/plugins/helm-push.git/bin/helm-cm-push
	// 对于语言包原样输出，对于系统包，需要做一定的处理
	target := vu.Target
	if util.ExistBit1(vu.Flag, VulnFlagClassOSPkg) {
		start := strings.Index(vu.Target, "(")
		last := strings.LastIndex(vu.Target, ")")
		if start >= 0 && last >= 0 && last > start && last < len(vu.Target) {
			target = string([]byte(vu.Target)[start+1 : last])
			target = strings.Join(strings.Split(target, " "), ":")
		} else {
			target = ""
		}
	}
	vu.Target = target

	if vu.Metadata != nil {
		split := strings.Split(vu.Metadata.CVSS.CVSSv3Vector, "/")
		for i := range split {
			attr := strings.Split(split[i], ":")
			if len(attr) >= 2 && vulnAttr[attr[0]] != nil {
				vu.Attr[attr[0]] = vulnAttr[attr[0]][attr[1]]
				vu.CvssMap[attr[0]] = vulnPosAttr[attr[0]][attr[1]]
			}
		}
	}
}

func (vu *Vuln) GenCheckSum() uint64 {
	createdAt, updatedAt, preCheck := vu.CreatedAt, vu.UpdatedAt, vu.CheckSum
	vu.CreatedAt = time.Time{}
	vu.UpdatedAt = time.Time{}
	vu.CheckSum = 0

	bys, err := json.Marshal(vu)
	vu.CreatedAt, vu.UpdatedAt, vu.CheckSum = createdAt, updatedAt, preCheck
	if err != nil {
		return 0
	}
	return util.GenerateUUID64(string(bys))
}

func (vu *Vuln) GenUniqueVuln() uint64 {
	key := fmt.Sprintf(consts.UniqueVulnFamat, vu.Name, vu.PkgName, vu.PkgVersion)
	uid := util.GenerateUUID64(key)
	return uid
}

// 漏洞关联镜像表
type VulnImage struct {
	ID          int64     `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time `gorm:"column:created_at" json:"createdAt"`
	UpdatedAt   time.Time `gorm:"column:updated_at"  json:"updatedAt"`
	UniqueVuln  uint64    `gorm:"column:unique_vuln" json:"uniqueVuln"` // 漏洞的唯一标识
	ImageId     int64     `gorm:"column:image_id" json:"imageId"`       // 镜像id
	LayerDigest string    `gorm:"column:layer_digest" json:"layerDigest"`
}

func (vi *VulnImage) Same(after *VulnImage) bool {
	if vi.ImageId != after.ImageId || vi.UniqueVuln != after.UniqueVuln || vi.LayerDigest != after.LayerDigest {
		return false
	}
	return true
}

func (*VulnImage) TableName() string {
	return "ivan_scanner_vuln_images"
}

// 漏洞表
type Vuln struct {
	ID           int64         `gorm:"primaryKey" json:"id"`
	UniqueVuln   uint64        `gorm:"column:unique_vuln" json:"unique_vuln,string"`
	Name         string        `gorm:"column:name" json:"name"` // 形如CVE-2021-28831
	CnnvdName    string        `gorm:"column:cnnvd_name" json:"cnnvdName"`
	Namespace    string        `gorm:"column:namespace" json:"namespace"`     // 发行版名字：alpine，redhat等
	Description  string        `gorm:"column:description" json:"description"` // 描述
	Link         []string      `gorm:"-" json:"link"`                         // 参考链接
	LinkJSON     []byte        `gorm:"column:link_json" json:"-"`
	Severity     string        `gorm:"column:severity" json:"severity"` // 威胁等级
	SeverityInt  int           `gorm:"column:severity_int" json:"severity_int"`
	Metadata     *VulnMatedata `gorm:"-" json:"metadata"`
	MetadataJSON []byte        `gorm:"column:metadata_json" json:"-"`         // 元数据
	PkgName      string        `gorm:"column:pkg_name" json:"pkg_name"`       // 软件包来源
	PkgVersion   string        `gorm:"column:pkg_version" json:"pkg_version"` // 软件包版本
	FixedBy      string        `gorm:"column:fixed_by" json:"fixedby"`        // 修复建议
	Target       string        `gorm:"column:target" json:"target"`
	ExtraInfo    []byte        `gorm:"type:Blob" json:"-"` //  预留，漏洞属性。如我们自己的漏洞评级
	CheckSum     uint64        `gorm:"column:check_sum" json:"check_sum,string"`
	Language     string        `gorm:"column:language" json:"language"` // 把编程语言入库用于搜索 统一存小写，便于搜索
	Frame        string        `gorm:"column:frame" json:"frame"`       // 开发框架筛选
	Class        string        `gorm:"column:class" json:"class"`       // 漏洞类型,2.11版本整合到flag字段中便于搜索，暂时保留，后续废弃
	Flag         uint64        `gorm:"column:flag" json:"flag,string"`
	CreatedAt    time.Time     `gorm:"column:created_at" json:"created_at"`
	UpdatedAt    time.Time     `gorm:"column:updated_at" json:"updated_at"`
	DeletedAt    int           `gorm:"column:deleted_at" json:"deleted_at"`

	Attr    map[string]string `gorm:"-" json:"attr"`    // 漏洞详情中雷达图的数据
	CvssMap map[string]string `gorm:"-" json:"cvssMap"` // 漏洞详情中雷达图的位置数据
}

// 漏洞类型
func (vu *Vuln) GetVulnClass() string {
	if util.ExistBit1(vu.Flag, VulnFlagClassOSPkg) {
		return "系统漏洞"
	} else if util.ExistBit1(vu.Flag, VulnFlagClassOSPkg) {
		return "应用漏洞"
	} else if util.ExistBit1(vu.Flag, VulnFlagClassConfig) {
		return "配置文件漏洞"
	}
	return ""
}
