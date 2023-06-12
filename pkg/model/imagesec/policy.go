package imagesec

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type SecurityPolicy struct {
	ID             int64               `gorm:"primaryKey" json:"id"`
	Name           string              `gorm:"column:name" json:"name"`
	IsDefault      bool                `gorm:"column:is_default" json:"isDefault"`
	Comment        string              `gorm:"column:comment" json:"comment"`
	ScopeJSON      string              `gorm:"column:scope" json:"-"`         //
	Scope          PolicyScope         `gorm:"-" json:"scope"`                //
	Creator        string              `gorm:"column:creator" json:"creator"` // 创建人
	Updater        string              `gorm:"column:updater" json:"updater"`
	MalwareJSON    string              `gorm:"column:malware" json:"-"`
	Malware        MalwareDetectRule   `gorm:"-" json:"malware"`
	WebshellJSON   string              `gorm:"column:webshell" json:"-"`
	Webshell       WebshellDetectRule  `gorm:"-" json:"webshell"`
	VulnJSON       string              `gorm:"column:vuln" json:"-"`
	Vuln           VulnDetectRule      `gorm:"-" json:"vuln"`
	SensitiveJSON  string              `gorm:"column:sensitive" json:"-"`
	Sensitive      SensitiveDetectRule `gorm:"-" json:"sensitive"`
	PkgJSON        string              `gorm:"column:pkg" json:"-"`
	Pkg            PkgRule             `gorm:"-" json:"pkg"`
	LicenseJSON    string              `gorm:"column:license" json:"-"`
	License        LicenseDetectRule   `gorm:"-" json:"license"`
	EnvJSON        string              `gorm:"column:env" json:"-"`
	Env            EnvDetectRule       `gorm:"-" json:"env"`
	RootBootEnable bool                `gorm:"column:root_boot_enable" json:"rootBootEnable"`           // 检测root用户启动
	CreatedAt      int64               `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt      int64               `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
	DeletedAt      int64               `gorm:"column:deleted_at" json:"deletedAt"`                      // milliseconds
}

func (vi *SecurityPolicy) ToUpdater() map[string]interface{} {
	updater := map[string]interface{}{
		"name":             vi.Name,
		"comment":          vi.Comment,
		"malware":          vi.MalwareJSON,
		"webshell":         vi.WebshellJSON,
		"vuln":             vi.VulnJSON,
		"sensitive":        vi.SensitiveJSON,
		"pkg":              vi.PkgJSON,
		"license":          vi.LicenseJSON,
		"root_boot_enable": vi.RootBootEnable,
		"scope":            vi.ScopeJSON,
		"updater":          vi.Updater,
		"updated_at":       time.Now().UnixMilli(),
	}
	return updater
}

type SecurityPolicyBrief struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	IsDefault bool   `json:"isDefault"`
}

func (vi *SecurityPolicy) ToSecurityPolicyBrief() *SecurityPolicyBrief {
	return &SecurityPolicyBrief{
		ID:        vi.ID,
		Name:      vi.Name,
		IsDefault: vi.IsDefault,
	}
}

func (vi *SecurityPolicy) Serialize() {
	vi.StripSpace()
	vi.Name = strings.TrimSpace(vi.Name)
	vi.Comment = strings.TrimSpace(vi.Comment)

	if vi.Updater == "" && vi.Creator != "" {
		vi.Updater = vi.Creator
	}

	if vi.Scope.ClusterKey == nil {
		vi.Scope.ClusterKey = make([]string, 0)
	}
	bys, _ := json.Marshal(vi.Scope)

	vi.ScopeJSON = string(bys)

	vi.Malware.White = util.DuplicateStringSlice(vi.Malware.White)
	bys, _ = json.Marshal(vi.Malware)
	vi.MalwareJSON = string(bys)

	vi.Webshell.White = util.DuplicateStringSlice(vi.Webshell.White)

	for i := range vi.Webshell.RiskLevel {
		vi.Webshell.RiskLevel[i] = strings.ToLower(vi.Webshell.RiskLevel[i])
	}
	bys, _ = json.Marshal(vi.Webshell)
	vi.WebshellJSON = string(bys)

	vi.Vuln.White = CusVulns(vi.Vuln.White).Deduplicate()
	vi.Vuln.Black = CusVulns(vi.Vuln.Black).Deduplicate()

	bys, _ = json.Marshal(vi.Vuln)
	vi.VulnJSON = string(bys)

	vi.Sensitive.White = util.DuplicateStringSlice(vi.Sensitive.White)
	vi.Sensitive.Black = util.DuplicateStringSlice(vi.Sensitive.Black)
	bys, _ = json.Marshal(vi.Sensitive)
	vi.SensitiveJSON = string(bys)

	vi.License.Black = util.DuplicateStringSlice(vi.License.Black)
	bys, _ = json.Marshal(vi.License)
	vi.LicenseJSON = string(bys)

	vi.Env.Black = util.DuplicateStringSlice(vi.Env.Black)
	bys, _ = json.Marshal(vi.Env)
	vi.EnvJSON = string(bys)

	vi.Pkg.Black = PkgPattens(vi.Pkg.Black).Deduplicate()
	bys, _ = json.Marshal(vi.Pkg)
	vi.PkgJSON = string(bys)
}

func (vi *SecurityPolicy) ChangePolicyName(ctx context.Context) *SecurityPolicy {

	la, ok := ctx.Value(AcceptLanguage).(string)

	if ok && la == model.LangEn && vi.IsDefault {
		vi.Name = DefaultPolicyNameEN
	}
	return vi
}

func (vi *SecurityPolicy) StripSpace() {
	vi.Updater = strings.TrimSpace(vi.Updater)
	vi.Creator = strings.TrimSpace(vi.Creator)
	vi.Malware.White = util.TripSpaceSlice(vi.Malware.White)
	vi.Sensitive.Black = util.TripSpaceSlice(vi.Sensitive.Black)
	vi.Sensitive.White = util.TripSpaceSlice(vi.Sensitive.White)
	vi.Webshell.White = util.TripSpaceSlice(vi.Webshell.White)
	vi.License.Black = util.TripSpaceSlice(vi.License.Black)
	vi.Env.Black = util.TripSpaceSlice(vi.Env.Black)

	for i := range vi.Vuln.White {
		vi.Vuln.White[i].PkgName = strings.TrimSpace(vi.Vuln.White[i].PkgName)
		vi.Vuln.White[i].PkgVersion = strings.TrimSpace(vi.Vuln.White[i].PkgVersion)
		vi.Vuln.White[i].VulnID = strings.TrimSpace(vi.Vuln.White[i].VulnID)
	}

	for i := range vi.Vuln.Black {
		vi.Vuln.Black[i].PkgName = strings.TrimSpace(vi.Vuln.Black[i].PkgName)
		vi.Vuln.Black[i].PkgVersion = strings.TrimSpace(vi.Vuln.Black[i].PkgVersion)
		vi.Vuln.Black[i].VulnID = strings.TrimSpace(vi.Vuln.Black[i].VulnID)
	}

	for i := range vi.Pkg.Black {
		vi.Pkg.Black[i].Name = strings.TrimSpace(vi.Pkg.Black[i].Name)
		vi.Pkg.Black[i].InstallVersion = strings.TrimSpace(vi.Pkg.Black[i].InstallVersion)
	}
}

func (vi *SecurityPolicy) Deserialize(cluster map[string]string) {
	_ = json.Unmarshal([]byte(vi.ScopeJSON), &vi.Scope)
	_ = json.Unmarshal([]byte(vi.MalwareJSON), &vi.Malware)
	_ = json.Unmarshal([]byte(vi.VulnJSON), &vi.Vuln)
	_ = json.Unmarshal([]byte(vi.SensitiveJSON), &vi.Sensitive)
	_ = json.Unmarshal([]byte(vi.PkgJSON), &vi.Pkg)
	_ = json.Unmarshal([]byte(vi.EnvJSON), &vi.Env)
	_ = json.Unmarshal([]byte(vi.WebshellJSON), &vi.Webshell)
	_ = json.Unmarshal([]byte(vi.LicenseJSON), &vi.License)

	vi.SetEmptySlice()

	for i := range vi.Scope.ClusterKey {
		vi.Scope.ClusterName = append(vi.Scope.ClusterName, cluster[vi.Scope.ClusterKey[i]])
	}
	if vi.Scope.AllCluster {
		for k, n := range cluster {
			vi.Scope.ClusterName = append(vi.Scope.ClusterName, n)
			vi.Scope.ClusterKey = append(vi.Scope.ClusterKey, k)
		}
	}
	vi.Scope.ClusterName = util.DuplicateStringSlice(vi.Scope.ClusterName)
	vi.Scope.ClusterKey = util.DuplicateStringSlice(vi.Scope.ClusterKey)
}

func (vi *SecurityPolicy) SetEmptySlice() {
	vi.Sensitive.Serialize()

	if len(vi.Scope.ClusterKey) == 0 {
		vi.Scope.ClusterKey = make([]string, 0)
	}

	if len(vi.Malware.White) == 0 {
		vi.Malware.White = make([]string, 0)
	}
	if len(vi.Vuln.White) == 0 {
		vi.Vuln.White = make([]CusVuln, 0)
	}
	if len(vi.Vuln.Black) == 0 {
		vi.Vuln.Black = make([]CusVuln, 0)
	}
	if len(vi.Sensitive.White) == 0 {
		vi.Sensitive.White = make([]string, 0)
	}
	if len(vi.Sensitive.Black) == 0 {
		vi.Sensitive.Black = make([]string, 0)
	}
	if len(vi.Pkg.Black) == 0 {
		vi.Pkg.Black = make([]PkgPatten, 0)
	}
	if len(vi.Env.Black) == 0 {
		vi.Env.Black = make([]string, 0)
	}

	if len(vi.Env.Black) == 0 {
		vi.Env.Black = make([]string, 0)
	}

	if len(vi.Webshell.White) == 0 {
		vi.Webshell.White = make([]string, 0)
	}
	if len(vi.License.Black) == 0 {
		vi.License.Black = make([]string, 0)
	}
	if len(vi.Scope.ClusterName) == 0 {
		vi.Scope.ClusterName = make([]string, 0)
	}
}

func (vi *SecurityPolicy) TableName() string {
	return "ivan_image_detect_policy"
}

func (vi *SecurityPolicy) Check() *i18.ErrI18 {
	if vi == nil {
		return i18.CreateI18BadReqErr("程序出错", "not get model")
	}
	if vi.Name == "" {
		return i18.CreateI18BadReqErr("未获取到策略名", "not get policy name")
	}
	if len([]rune(vi.Name)) > 50 {
		return i18.CreateI18BadReqErr("策略名限定50个字符", "name more than 50")
	}
	if vi.Creator == "" && vi.Updater == "" {
		return i18.CreateI18BadReqErr("未获取到创建人或更新人", "not get creator or updater")
	}

	if len([]rune(vi.Comment)) > 150 {
		return i18.CreateI18BadReqErr("备注限定150个字符", "comment more than 150")
	}
	if err := vi.Scope.Check(); err != nil {
		return err
	}
	if err := vi.Webshell.Check(); err != nil {
		return err
	}
	if vi.License.Enable && len(vi.License.Black) == 0 {
		return i18.CreateI18BadReqErr("未获取到需要检测的开源协议", "not get exception license")
	}
	if vi.Sensitive.Enable && (len(vi.Sensitive.Black) == 0 && !vi.Sensitive.AllBlack) && (!vi.Sensitive.AllWhite && len(vi.Sensitive.White) == 0) {
		return i18.CreateI18BadReqErr("未获取到需要检测的敏感文件", "not get exception sensitive file")
	}
	if vi.Pkg.Enable && len(vi.Pkg.Black) == 0 {
		return i18.CreateI18BadReqErr("未获取到需要检测的软件", "not get exception pkg")
	}

	return nil
}

type MalwareDetectRule struct {
	Enable bool     `json:"enable"`
	Action string   `json:"action"`
	White  []string `json:"white"`
}

type WebshellDetectRule struct {
	Enable    bool     `json:"enable"`
	Action    string   `json:"action"`
	RiskLevel []string `json:"riskLevel"`
	White     []string `json:"white"`
}

func (vi *WebshellDetectRule) Check() *i18.ErrI18 {
	if vi.Enable && len(vi.RiskLevel) == 0 {
		return i18.CreateI18BadReqErr("未获取到 webshell 风险层级", "not get webshell risk level")
	}
	for i := range vi.RiskLevel {
		if !util.ExistInStringSlice([]string{WebshellRiskLevelCertain, WebshellRiskLevelMaybe}, vi.RiskLevel[i]) {
			return i18.CreateI18BadReqErr("webshell 风险层级不正确", "webshell risk leve incorrect")
		}
	}
	return nil
}

type VulnDetectRule struct {
	Enable           bool      `json:"enable"`
	Action           string    `json:"action"`
	Severity         string    `json:"severity"`
	Black            []CusVuln `json:"black"` // 自定义漏洞（黑名单）
	White            []CusVuln `json:"white"` // 加白
	IgnoreUnfixed    bool      `json:"ignoreUnfixed"`
	IgnoreKernelVuln bool      `json:"ignoreKernelVuln"`
	IgnoreLangVuln   bool      `json:"ignoreLangVuln"`
}

type CusVuln struct {
	VulnID     string `json:"vulnID"`
	PkgName    string `json:"pkgName"`
	PkgVersion string `json:"pkgVersion"`
}

type CusVulns []CusVuln

func (vi CusVulns) Deduplicate() []CusVuln {
	hasPkg := make(map[string]bool)
	for i := range vi {
		if vi[i].PkgName != "" {
			hasPkg[vi[i].VulnID] = true
		}
	}
	exit := make(map[string]bool)
	ans := make([]CusVuln, 0)
	for i := range vi {
		key := fmt.Sprintf("%s|%s|%s", vi[i].VulnID, vi[i].PkgName, vi[i].PkgVersion)
		if hasPkg[vi[i].VulnID] && (vi[i].PkgName == "" && vi[i].PkgVersion == "") {
			continue
		}
		if !exit[key] {
			ans = append(ans, vi[i])
			exit[key] = true
		}
	}
	return ans
}

type SensitiveDetectPatten struct {
	Description string `json:"description"`
	Value       string `json:"value"`
	RuleType    string `json:"ruleType"`
}

type SensitiveDetectRule struct {
	Enable   bool     `json:"enable"`
	Action   string   `json:"action"`
	AllBlack bool     `json:"allBlack"`
	AllWhite bool     `json:"allWhite"`
	White    []string `json:"white"` // 正则
	Black    []string `json:"black"`
}

func (vi *SensitiveDetectRule) Serialize() {
	if vi.AllBlack {
		vi.Black = make([]string, 0)
	}
	if vi.AllWhite {
		vi.White = make([]string, 0)
	}
}

type PkgRule struct {
	Enable bool        `json:"enable"`
	Action string      `json:"action"`
	Black  []PkgPatten `json:"black"` // 黑名单
}

type PkgPatten struct {
	Name           string `json:"name"`
	InstallVersion string `json:"installVersion"`
}

type PkgPattens []PkgPatten

func (vi PkgPattens) Deduplicate() []PkgPatten {
	ans := make([]PkgPatten, 0)
	pkgExit := make(map[string]bool)
	for i := range vi {
		key := vi[i].Name + "|" + vi[i].InstallVersion
		if !pkgExit[key] {
			ans = append(ans, vi[i])
		}
		pkgExit[key] = true
	}
	return ans
}

type LicenseDetectRule struct {
	Enable bool     `json:"enable"`
	Action string   `json:"action"`
	Black  []string `json:"black"`
}

type EnvDetectRule struct {
	Enable        bool     `json:"enable"`
	Action        string   `json:"action"`
	CheckPassword bool     `json:"checkPassword"`
	Black         []string `json:"black"`
}

type PolicyScope struct {
	ImageRegexp   string   `json:"imageRegexp"`
	ClusterKey    []string `json:"clusterKey"`
	AllCluster    bool     `json:"allCluster"`
	ImageFromType string   `json:"imageFromType"`
	ScopeType     string   `json:"scopeType"`
	ClusterName   []string `json:"clusterName"`
}

func (vi *PolicyScope) Check() *i18.ErrI18 {
	if vi.ImageRegexp == "" && (len(vi.ClusterKey) == 0 && !vi.AllCluster) {
		return i18.CreateI18BadReqErr("未获取到策略适用范围", "not get policy scope")
	}
	if vi.ImageRegexp != "" {
		if _, err := regexp.Compile(vi.ImageRegexp); err != nil {
			return i18.CreateI18BadReqErr("镜像正则表达出错", "image scope regexp fail")
		}
	}
	if vi.ImageFromType == "" {
		return i18.CreateI18BadReqErr("not get ImageFromType", "not get ImageFromType")
	}
	if vi.ScopeType == "" {
		return i18.CreateI18BadReqErr("未获取到周期类型", "not get scope type")
	}
	return nil
}

const (
	DefaultPolicyNameZH = "默认安全策略"
	DefaultPolicyNameEN = "default policy"
)
