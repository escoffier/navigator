package imagesec

import (
	"strings"
	"sync"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var vulnVectorAttrWithZHView map[string]map[string]string

// var vulnVectorAttrWithZHView map[string]string
var vulnPosAttr map[string]map[string]string
var vulnVectorFlag map[string]map[string]uint64
var defaultAttr map[string]string
var languageMap map[string]string

func GetVulnAVView(lang string) map[string]string {
	avCH := map[string]string{
		"N": "网络访问",
		"L": "本地访问",
		"P": "物理访问",
		"A": "相邻网络访问", // https://www.first.org/cvss/calculator/3.1
	}

	avEn := map[string]string{
		"N": "Network",
		"L": "local",
		"P": "Physical",
		"A": "Adjacent", // https://www.first.org/cvss/calculator/3.1
	}
	if lang == model.LangEn {
		return avEn
	}

	return avCH
}

func GetVulnUIView(lang string) map[string]string {
	avCH := map[string]string{
		"N": "自动",
		"R": "非自动",
	}

	avEn := map[string]string{
		"N": "None",
		"R": "Required",
	}
	if lang == model.LangEn {
		return avEn
	}

	return avCH
}

func GetVulnAcView(lang string) map[string]string {
	avCH := map[string]string{
		"N": "无",
		"L": "低",
		"H": "高",
	}

	avEn := map[string]string{
		"N": "None",
		"L": "Low",
		"H": "High",
	}
	if lang == model.LangEn {
		return avEn
	}

	return avCH
}

func GetVulnPrView(lang string) map[string]string {
	avCH := map[string]string{
		"N": "无",
		"L": "低",
		"H": "高",
	}

	avEn := map[string]string{
		"N": "None",
		"L": "Low",
		"H": "High",
	}
	if lang == model.LangEn {
		return avEn
	}

	return avCH
}

func GetVulnCView(lang string) map[string]string {
	avCH := map[string]string{
		"N": "无",
		"L": "低",
		"H": "高",
	}

	avEn := map[string]string{
		"N": "None",
		"L": "Low",
		"H": "High",
	}
	if lang == model.LangEn {
		return avEn
	}

	return avCH
}

func GetVulnAView(lang string) map[string]string {
	avCH := map[string]string{
		"N": "无",
		"L": "低",
		"H": "高",
	}

	avEn := map[string]string{
		"N": "None",
		"L": "Low",
		"H": "High",
	}
	if lang == model.LangEn {
		return avEn
	}

	return avCH
}

func GetVulnIView(lang string) map[string]string {
	avCH := map[string]string{
		"N": "无",
		"L": "低",
		"H": "高",
	}

	avEn := map[string]string{
		"N": "None",
		"L": "Low",
		"H": "High",
	}
	if lang == model.LangEn {
		return avEn
	}

	return avCH
}

func GetVulnSView(lang string) map[string]string {
	avCH := map[string]string{
		"C": "扩大",
		"U": "不变",
	}

	avEn := map[string]string{
		"C": "Enlarge",
		"U": "Unchanged",
	}
	if lang == model.LangEn {
		return avEn
	}

	return avCH
}

func init() {
	var once sync.Once
	once.Do(func() {
		vulnVectorAttrWithZHView = make(map[string]map[string]string)
		// 攻击位置难易
		vulnVectorAttrWithZHView["AV"] = map[string]string{
			"N": "网络访问",
			"L": "本地访问",
			"P": "物理访问",
			"":  "相邻网络访问",
			"A": "相邻网络访问", // https://www.first.org/cvss/calculator/3.1
		}
		// 是否自动化触发
		vulnVectorAttrWithZHView["UI"] = map[string]string{
			"N": "自动",
			"R": "非自动",
		}
		//  攻击复杂度
		vulnVectorAttrWithZHView["AC"] = map[string]string{
			"N": "无",
			"L": "低",
			"H": "高",
		}
		// 信息泄露风险
		vulnVectorAttrWithZHView["C"] = map[string]string{
			"N": "无",
			"L": "低",
			"H": "高",
		}
		// 信息/系统篡改风险
		vulnVectorAttrWithZHView["A"] = map[string]string{
			"N": "无",
			"L": "低",
			"H": "高",
		}
		//  权限范围扩大
		vulnVectorAttrWithZHView["S"] = map[string]string{
			"C": "扩大",
			"U": "不变",
		}
		// 造成 DoS 风险
		vulnVectorAttrWithZHView["PR"] = map[string]string{
			"N": "无",
			"L": "低",
			"H": "高",
		}

		defaultAttr = map[string]string{
			"AV": "A", // 攻击位置难易
			"UI": "R", // 是否自动化触发
			"AC": "N", // 攻击复杂度
			"C":  "N", // 信息泄露风险
			"A":  "N", // 信息/系统篡改风险
			"PR": "N", // 所需权限级别
			"S":  "U", // 权限范围扩大
			"I":  "N", // 触发dos风险
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

		vulnVectorFlag = make(map[string]map[string]uint64)
		// 攻击位置难易
		vulnVectorFlag["AV"] = map[string]uint64{
			"N": CVSSFlagAVN,
			"L": CVSSFlagAVL,
			"P": CVSSFlagAVP,
			"":  CVSSFlagAVA,
			"A": CVSSFlagAVA, // https://www.first.org/cvss/calculator/3.1
		}
		// 是否自动化触发
		vulnVectorFlag["UI"] = map[string]uint64{
			"N": CVSSFlagUIN,
			"R": CVSSFlagUIR,
		}
		// 所需权限级别 and 攻击复杂度
		vulnVectorFlag["AC"] = map[string]uint64{
			"N": CVSSFlagACN,
			"L": CVSSFlagACL,
			"H": CVSSFlagACH,
		}
		// 信息泄露风险
		vulnVectorFlag["C"] = map[string]uint64{
			"N": CVSSFlagCN,
			"L": CVSSFlagCL,
			"H": CVSSFlagCH,
		}
		// 信息/系统篡改风险
		vulnVectorFlag["A"] = map[string]uint64{
			"N": CVSSFlagAN,
			"L": CVSSFlagAL,
			"H": CVSSFlagAH,
		}
		//  权限范围扩大
		vulnVectorFlag["S"] = map[string]uint64{
			"C": CVSSFlagSC,
			"U": CVSSFlagSU,
		}
		// 造成 DoS 风险
		vulnVectorFlag["PR"] = map[string]uint64{
			"N": CVSSFlagPRN,
			"L": CVSSFlagPRL,
			"H": CVSSFlagPRH,
		}

		languageMap = map[string]string{
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
	})
}

type SeverityGroups []SeverityGroup

func (sgs SeverityGroups) Len() int {
	return len(sgs)
}

func (sgs SeverityGroups) Less(i, j int) bool {
	if sgs[i].SeverityInt > sgs[j].SeverityInt {
		return true
	} else if sgs[i].SeverityInt < sgs[j].SeverityInt {
		return false
	} else if sgs[i].SeverityInt == sgs[j].SeverityInt {
		return sgs[i].Count > sgs[j].Count
	}
	return true
}

func (sgs SeverityGroups) Swap(i, j int) {
	sgs[i], sgs[j] = sgs[j], sgs[i]
}

func AddSeverityGroup(sgs []SeverityGroup, severityInt int64) []SeverityGroup {
	needAdd := true
	for i := range sgs {
		if sgs[i].SeverityInt == severityInt {
			needAdd = false
			sgs[i].Count++
		}
	}
	if needAdd {
		sgs = append(sgs, SeverityGroup{
			SeverityInt: severityInt,
			Count:       1,
			Severity:    model.GetSeverity(severityInt),
		})
	}
	return sgs
}

type SeverityGroup struct {
	SeverityInt int64  `gorm:"column:severity_int" json:"severityInt"`
	Severity    string `gorm:"column:severity" json:"severity"`
	Count       int64  `gorm:"column:cnt"  json:"count"`
}

func GetDefaultAttr() map[string]string {
	attr := make(map[string]string)
	for k, v := range defaultAttr {
		attr[k] = v
	}
	return attr
}

// "cvssV3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L",
func genCVSSv3Vector(v3Vector string) map[string]string {
	ans := make(map[string]string)
	if v3Vector == "" {
		return GetDefaultAttr()
	}

	split := strings.Split(v3Vector, "/")
	for i := range split {
		attr := strings.Split(split[i], ":")
		if len(attr) >= 2 && attr[0] != "CVSS" {
			ans[attr[0]] = attr[1]
		}
	}
	return ans
}

func genCVSSv2Vector(v2Vector string) map[string]string {
	ans := make(map[string]string)
	return ans
}

type LabelValue struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type VulnLangConstView struct {
	ZH VuluConstView `json:"zh"`
	EN VuluConstView `json:"en"`
}

type VuluConstView struct {
	AttackPath []LabelValue `json:"attackPath"`
	Class      []LabelValue `json:"class"`
	Severity   []LabelValue `json:"severity"`
}
