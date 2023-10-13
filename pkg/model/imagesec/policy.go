package imagesec

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type SecurityPolicy struct {
	ID             int64               `gorm:"primaryKey" json:"id"`
	UniqueID       uint64              `gorm:"column:unique_id" json:"uniqueID,string"`
	PolicyType     string              `gorm:"column:policy_type" json:"policyType"` // 配置类型,仓库镜像检测，节点镜像检测，部署上线阻断策略
	DeployMod      string              `gorm:"column:deploy_mod" json:"deployMod"`   // 基础模式，安全模式(部署上线特有)
	Name           string              `gorm:"column:name" json:"name"`
	Enable         bool                `gorm:"column:enable" json:"enable"` // 是否开启动
	IsDefault      bool                `gorm:"column:is_default" json:"isDefault"`
	Comment        string              `gorm:"column:comment" json:"comment"`
	ScopeJSON      string              `gorm:"column:scope" json:"-"`         //
	Scope          PolicyScope         `gorm:"-" json:"scope"`                //
	Creator        string              `gorm:"column:creator" json:"creator"` // 创建人
	MalwareJSON    string              `gorm:"column:malware" json:"-"`
	Malware        MalwareDetectRule   `gorm:"-" json:"malware"`
	WebshellJSON   string              `gorm:"column:webshell" json:"-"`
	Webshell       WebshellDetectRule  `gorm:"-" json:"webshell"`
	VulnJSON       string              `gorm:"column:vuln" json:"-"`
	VulnDB         VulnDetectRule      `gorm:"-" json:"vulnDB"` // 后端保存及检测的数据
	Vuln           VulnDetectRuleView  `gorm:"-" json:"vuln"`   // 前端给的数据，及展示的数据
	SensitiveJSON  string              `gorm:"column:sensitive" json:"-"`
	Sensitive      SensitiveDetectRule `gorm:"-" json:"sensitive"`
	PkgJSON        string              `gorm:"column:pkg" json:"-"`
	Pkg            PkgRule             `gorm:"-" json:"pkg"`
	LicenseJSON    string              `gorm:"column:license" json:"-"`
	License        LicenseDetectRule   `gorm:"-" json:"license"`
	PkgLicenseJSON string              `gorm:"column:pkg_license" json:"-"`
	PkgLicense     LicenseDetectRule   `gorm:"-" json:"pkgLicense"`
	EnvJSON        string              `gorm:"column:env" json:"-"`
	Env            EnvDetectRule       `gorm:"-" json:"env"`
	RootBootJSON   string              `gorm:"column:root_boot" json:"-"` // 检测root用户启动
	RootBoot       EnableActionRule    `gorm:"-" json:"rootBoot"`         // 检测root用户启动
	TrustImageJSON string              `gorm:"column:trust_image" json:"-"`
	TrustImage     EnableActionRule    `gorm:"-" json:"trustImage"` // 可信镜像
	BaseImageJSON  string              `gorm:"column:base_image" json:"-"`
	BaseImage      EnableActionRule    `gorm:"-" json:"baseImage"`
	ExistInRegJSON string              `gorm:"column:exist_in_reg" json:"-"`
	ExistInReg     EnableActionRule    `gorm:"-" json:"existInReg"`
	Updater        string              `gorm:"column:updater" json:"updater"`

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
	DeletedAt int64 `gorm:"column:deleted_at" json:"deletedAt"`                      // milliseconds
}

func (vi *SecurityPolicy) ToUpdater() map[string]interface{} {
	updater := map[string]interface{}{
		"enable":       vi.Enable,
		"name":         vi.Name,
		"deploy_mod":   vi.DeployMod,
		"comment":      vi.Comment,
		"scope":        vi.ScopeJSON,
		"malware":      vi.MalwareJSON,
		"webshell":     vi.WebshellJSON,
		"vuln":         vi.VulnJSON,
		"sensitive":    vi.SensitiveJSON,
		"pkg":          vi.PkgJSON,
		"license":      vi.LicenseJSON,
		"pkg_license":  vi.PkgLicenseJSON,
		"env":          vi.EnvJSON,
		"root_boot":    vi.RootBootJSON,
		"trust_image":  vi.TrustImageJSON,
		"base_image":   vi.BaseImageJSON,
		"exist_in_reg": vi.ExistInRegJSON,
		"updater":      vi.Updater,
		"unique_id":    vi.UniqueID,
		"updated_at":   time.Now().UnixMilli(),
	}
	return updater
}

func (vi *SecurityPolicy) SetEmptyIfAll() {
	if vi.Scope.AllCluster {
		vi.Scope.ClusterKey = make([]string, 0)
		vi.Scope.ClusterName = make([]string, 0)
	}
	if vi.Scope.AllReg {
		vi.Scope.RegIds = make([]int64, 0)
		vi.Scope.RegName = make([]string, 0)
	}
	if vi.Sensitive.AllBlack {
		vi.Sensitive.Black = make([]string, 0)
	}
	if vi.Sensitive.AllWhite {
		vi.Sensitive.White = make([]string, 0)
	}
	if len(vi.Scope.ImageRegexp) == 0 {
		vi.Scope.ImageRegexp = make([]string, 0)
	}
}

type SecurityPolicyBrief struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	IsDefault bool   `json:"isDefault"`
}

func (vi *SecurityPolicy) GenUniqueID() uint64 {
	// 不可以重复生成
	if vi.UniqueID > 0 {
		return vi.UniqueID
	}
	id, updatedAt, createdAt, deletedAt := vi.ID, vi.UpdatedAt, vi.CreatedAt, vi.DeletedAt
	vi.UniqueID = 0
	bts, _ := json.Marshal(vi)
	uuid64 := util.GenerateUUID64(string(bts))
	vi.ID, vi.CreatedAt, vi.UpdatedAt, vi.DeletedAt = id, createdAt, updatedAt, deletedAt

	vi.UniqueID = uuid64
	return uuid64
}

func (vi *SecurityPolicy) ToSecurityPolicyBrief() *SecurityPolicyBrief {
	return &SecurityPolicyBrief{
		ID:        vi.ID,
		Name:      vi.Name,
		IsDefault: vi.IsDefault,
	}
}

func (vi *SecurityPolicy) Same(after *SecurityPolicy) bool {
	// 🐶 即使 enable 变动，生成的 UniqueID是一样的，
	return false
}

func (vi *SecurityPolicy) Serialize() {
	vi.StripSpace()
	vi.SetEmptySlice()

	vi.VulnDB = vi.Vuln.ToVulnDetectRule()

	vi.Name = strings.TrimSpace(vi.Name)
	vi.Comment = strings.TrimSpace(vi.Comment)

	if vi.Scope.ScopeType == DetectScopeTypeImage {
		vi.Scope.RegIds = make([]int64, 0)
		vi.Scope.RegName = make([]string, 0)
		vi.Scope.AllReg = false
	}
	if vi.Scope.ScopeType == DetectScopeTypeCluster || vi.Scope.ScopeType == DetectScopeTypeReg {
		vi.Scope.ImageRegexp = make([]string, 0)
	}

	switch vi.PolicyType {

	case ConfigTypeNodeScanImage:
		vi.Scope.ImageFromType = ImageFromNode
		vi.Enable = true
	case ConfigTypeRegScanImage:
		vi.Scope.ImageFromType = ImageFromRegistry
		vi.Enable = true
	case ConfigTypeDeploy:
		vi.Scope.ImageFromType = ImageFromRegistry
		vi.Scope.ScopeType = DetectScopeTypeImage
	}

	if vi.Updater == "" && vi.Creator != "" {
		vi.Updater = vi.Creator
	}
	vi.Scope.Serialize()
	bys1, _ := json.Marshal(vi.Scope)

	vi.ScopeJSON = string(bys1)

	vi.Malware.White = util.DuplicateStringSlice(vi.Malware.White)
	bys2, _ := json.Marshal(vi.Malware)
	vi.MalwareJSON = string(bys2)

	vi.Webshell.White = util.DuplicateStringSlice(vi.Webshell.White)

	for i := range vi.Webshell.RiskLevel {
		vi.Webshell.RiskLevel[i] = strings.ToLower(vi.Webshell.RiskLevel[i])
	}
	bys3, _ := json.Marshal(vi.Webshell)
	vi.WebshellJSON = string(bys3)

	vi.VulnDB.White = CusVulns(vi.VulnDB.White).Deduplicate()
	vi.VulnDB.Black = CusVulns(vi.VulnDB.Black).Deduplicate()

	bys4, _ := json.Marshal(vi.VulnDB)
	vi.VulnJSON = string(bys4)

	vi.Sensitive.White = util.DuplicateStringSlice(vi.Sensitive.White)
	vi.Sensitive.Black = util.DuplicateStringSlice(vi.Sensitive.Black)

	bys5, _ := json.Marshal(vi.Sensitive)
	vi.SensitiveJSON = string(bys5)

	vi.License.Black = util.DuplicateStringSlice(vi.License.Black)
	bys6, _ := json.Marshal(vi.License)
	vi.LicenseJSON = string(bys6)

	vi.Env.Black = util.DuplicateStringSlice(vi.Env.Black)
	bys7, _ := json.Marshal(vi.Env)
	vi.EnvJSON = string(bys7)

	vi.Pkg.Black = PkgPattens(vi.Pkg.Black).Deduplicate()
	bys8, _ := json.Marshal(vi.Pkg)
	vi.PkgJSON = string(bys8)

	vi.PkgLicense.Black = util.DuplicateStringSlice(vi.PkgLicense.Black)
	bys9, _ := json.Marshal(vi.PkgLicense)
	vi.PkgLicenseJSON = string(bys9)

	bys10, _ := json.Marshal(vi.TrustImage)
	vi.TrustImageJSON = string(bys10)

	bys11, _ := json.Marshal(vi.RootBoot)
	vi.RootBootJSON = string(bys11)

	bys13, _ := json.Marshal(vi.BaseImage)
	vi.BaseImageJSON = string(bys13)

	bys14, _ := json.Marshal(vi.ExistInReg)
	vi.ExistInRegJSON = string(bys14)

	if vi.UpdatedAt == 0 {
		vi.UpdatedAt = time.Now().UnixMilli()
	}
	if vi.CreatedAt == 0 {
		vi.CreatedAt = time.Now().UnixMilli()
	}

	vi.UniqueID = vi.GenUniqueID()
}

func (vi *SecurityPolicy) ChangePolicyName(ctx context.Context) *SecurityPolicy {
	if vi == nil {
		return nil
	}
	la, ok := ctx.Value(AcceptLanguage).(string)

	if ok && la == model.LangZh && (vi.IsDefault || vi.Name == DefaultPolicyNameEN) {
		vi.Name = DefaultPolicyNameZH
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

	for i := range vi.VulnDB.White {
		vi.VulnDB.White[i].PkgName = strings.TrimSpace(vi.VulnDB.White[i].PkgName)
		vi.VulnDB.White[i].PkgVersion = strings.TrimSpace(vi.VulnDB.White[i].PkgVersion)
		vi.VulnDB.White[i].VulnID = strings.TrimSpace(vi.VulnDB.White[i].VulnID)
	}

	for i := range vi.VulnDB.Black {
		vi.VulnDB.Black[i].PkgName = strings.TrimSpace(vi.VulnDB.Black[i].PkgName)
		vi.VulnDB.Black[i].PkgVersion = strings.TrimSpace(vi.VulnDB.Black[i].PkgVersion)
		vi.VulnDB.Black[i].VulnID = strings.TrimSpace(vi.VulnDB.Black[i].VulnID)
	}

	for i := range vi.Pkg.Black {
		vi.Pkg.Black[i].Name = strings.TrimSpace(vi.Pkg.Black[i].Name)
		vi.Pkg.Black[i].InstallVersion = strings.TrimSpace(vi.Pkg.Black[i].InstallVersion)
	}

	if vi.Sensitive.AllBlack {
		vi.Sensitive.Black = make([]string, 0)
	}
	if vi.Sensitive.AllWhite {
		vi.Sensitive.White = make([]string, 0)
	}
}

func (vi *SecurityPolicy) Deserialize(clusterName map[string]string, regName map[int64]string) {
	_ = json.Unmarshal([]byte(vi.ScopeJSON), &vi.Scope)
	_ = json.Unmarshal([]byte(vi.MalwareJSON), &vi.Malware)
	_ = json.Unmarshal([]byte(vi.VulnJSON), &vi.VulnDB)
	_ = json.Unmarshal([]byte(vi.SensitiveJSON), &vi.Sensitive)
	_ = json.Unmarshal([]byte(vi.PkgJSON), &vi.Pkg)
	_ = json.Unmarshal([]byte(vi.EnvJSON), &vi.Env)
	_ = json.Unmarshal([]byte(vi.WebshellJSON), &vi.Webshell)
	_ = json.Unmarshal([]byte(vi.LicenseJSON), &vi.License)
	_ = json.Unmarshal([]byte(vi.PkgLicenseJSON), &vi.PkgLicense)
	_ = json.Unmarshal([]byte(vi.TrustImageJSON), &vi.TrustImage)
	_ = json.Unmarshal([]byte(vi.BaseImageJSON), &vi.BaseImage)
	_ = json.Unmarshal([]byte(vi.RootBootJSON), &vi.RootBoot)
	_ = json.Unmarshal([]byte(vi.ExistInRegJSON), &vi.ExistInReg)

	vi.Vuln = vi.VulnDB.ToVulnDetectRuleView()

	vi.SetEmptySlice()

	vi.Scope.ClusterName = make([]string, 0)
	for i := range vi.Scope.ClusterKey {
		vi.Scope.ClusterName = append(vi.Scope.ClusterName, clusterName[vi.Scope.ClusterKey[i]])
	}

	vi.Scope.RegName = make([]string, 0)
	for i := range vi.Scope.RegIds {
		vi.Scope.RegName = append(vi.Scope.RegName, regName[vi.Scope.RegIds[i]])
	}

	if vi.Scope.AllCluster {
		for k, n := range clusterName {
			vi.Scope.ClusterName = append(vi.Scope.ClusterName, n)
			vi.Scope.ClusterKey = append(vi.Scope.ClusterKey, k)
		}
	}

	if vi.Scope.AllReg {
		for k, n := range regName {
			vi.Scope.RegName = append(vi.Scope.RegName, n)
			vi.Scope.RegIds = append(vi.Scope.RegIds, k)
		}
	}

	vi.Scope.ClusterName = util.DuplicateStringSlice(vi.Scope.ClusterName)
	vi.Scope.ClusterKey = util.DuplicateStringSlice(vi.Scope.ClusterKey)
	vi.Scope.RegName = util.DuplicateStringSlice(vi.Scope.RegName)
	vi.Scope.RegIds = util.DuplicateInt64Slice(vi.Scope.RegIds)

	if vi.Scope.ScopeType == DetectScopeTypeImage {
		vi.Scope.RegIds = make([]int64, 0)
		vi.Scope.AllReg = false
		vi.Scope.RegName = make([]string, 0)
	}
	if vi.Scope.ScopeType == DetectScopeTypeCluster || vi.Scope.ScopeType == DetectScopeTypeReg {
		vi.Scope.ImageRegexp = make([]string, 0)
	}
}

func (vi *SecurityPolicy) SetEmptySlice() {
	vi.Sensitive.Serialize()

	if len(vi.Scope.ClusterKey) == 0 {
		vi.Scope.ClusterKey = make([]string, 0)
	}
	if len(vi.Scope.RegIds) == 0 {
		vi.Scope.RegIds = make([]int64, 0)
	}

	if len(vi.Malware.White) == 0 {
		vi.Malware.White = make([]string, 0)
	}
	if len(vi.VulnDB.White) == 0 {
		vi.VulnDB.White = make([]CusVuln, 0)
	}
	if len(vi.VulnDB.Black) == 0 {
		vi.VulnDB.Black = make([]CusVuln, 0)
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
	if len(vi.Scope.RegName) == 0 {
		vi.Scope.RegName = make([]string, 0)
	}
	for i := range vi.Vuln.Black {
		if len(vi.Vuln.Black[i].PKG) == 0 {
			vi.Vuln.Black[i].PKG = make([]CusPkg, 0)
		}
	}

	for i := range vi.Vuln.White {
		if len(vi.Vuln.White[i].PKG) == 0 {
			vi.Vuln.White[i].PKG = make([]CusPkg, 0)
		}
	}
	if len(vi.Scope.ImageRegexp) == 0 {
		vi.Scope.ImageRegexp = make([]string, 0)
	}
}

func (vi *SecurityPolicy) TableName() string {
	return "ivan_image_detect_policy"
}

func (vi *SecurityPolicy) Check() error {
	if vi == nil {
		return i18.CreateI18BadReqErr("程序出错", "not get model")
	}
	if vi.PolicyType == "" {
		return i18.CreateI18BadReqErr("未获取到策略类型", "not get policy type")
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
	if vi.PkgLicense.Enable && len(vi.PkgLicense.Black) == 0 {
		return i18.CreateI18BadReqErr("未获取到需要检测的软件开源许可", "not get exception pkg-license")
	}
	if vi.PolicyType == ConfigTypeDeploy {
		if err := vi.deployPolicyCheck(); err != nil {
			return err
		}
	}
	if vi.PolicyType == ConfigTypeDeploy {
		vi.Scope.ScopeType = DetectScopeTypeImage
	}
	if err := vi.Scope.Check(); err != nil {
		return err
	}

	return nil
}

func checkAction(str string) bool {
	if str != DeployActionAlarm && str != DeployActionBlock {
		return false
	}
	return true
}

func (vi *SecurityPolicy) deployPolicyCheck() error {
	action := true
	if vi.TrustImage.Enable && !checkAction(vi.TrustImage.Action) {
		action = false
	}
	if vi.RootBoot.Enable && !checkAction(vi.RootBoot.Action) {
		action = false
	}

	if vi.Pkg.Enable && !checkAction(vi.Pkg.Action) {
		action = false
	}
	if vi.PkgLicense.Enable && !checkAction(vi.PkgLicense.Action) {
		action = false
	}
	if vi.VulnDB.Enable && !checkAction(vi.VulnDB.Action) {
		action = false
	}
	if vi.Env.Enable && !checkAction(vi.Env.Action) {
		action = false
	}
	if vi.Webshell.Enable && !checkAction(vi.Webshell.Action) {
		action = false
	}
	if vi.Malware.Enable && !checkAction(vi.Malware.Action) {
		action = false
	}

	if vi.Sensitive.Enable && !checkAction(vi.Sensitive.Action) {
		action = false
	}

	if !action {
		return i18.CreateI18BadReqErr("阻断策略动作未设置正确", "policy action not correct")
	}

	if vi.DeployMod != DeployModSafe && vi.DeployMod != DeployModBase {
		return i18.CreateI18BadReqErr("阻断模式未设置正确", "policy mode not correct")
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

func (vi *WebshellDetectRule) Check() error {
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

type VulnDetectRuleView struct {
	Enable           bool          `json:"enable"`
	Action           string        `json:"action"`
	Severity         string        `json:"severity"`
	Black            []CusVulnView `json:"black"` // 自定义漏洞（黑名单）
	White            []CusVulnView `json:"white"` // 加白
	IgnoreUnfixed    bool          `json:"ignoreUnfixed"`
	IgnoreKernelVuln bool          `json:"ignoreKernelVuln"`
	IgnoreLangVuln   bool          `json:"ignoreLangVuln"`
	HasFixedVuln     bool          `json:"hasFixedVuln"` // 存在可修复漏洞
}

func (vi *VulnDetectRuleView) ToVulnDetectRule() VulnDetectRule {
	res := VulnDetectRule{
		Enable:           vi.Enable,
		Action:           vi.Action,
		Severity:         vi.Severity,
		Black:            make([]CusVuln, 0),
		White:            make([]CusVuln, 0),
		IgnoreUnfixed:    vi.IgnoreUnfixed,
		IgnoreKernelVuln: vi.IgnoreKernelVuln,
		IgnoreLangVuln:   vi.IgnoreLangVuln,
		HasFixedVuln:     vi.HasFixedVuln,
	}
	for i := range vi.White {
		vu := CusVuln{
			VulnID: vi.White[i].VulnID,
		}
		hasPkg := false
		for j := range vi.White[i].PKG {
			pg := vi.White[i].PKG[j]
			hasPkg = true
			vu1 := vu.DeepCopy()
			vu1.PkgName = pg.PkgName
			vu1.PkgVersion = pg.PkgVersion
			res.White = append(res.White, vu1)
		}
		if !hasPkg {
			res.White = append(res.White, vu)
		}
	}

	for i := range vi.Black {
		vu := CusVuln{
			VulnID: vi.Black[i].VulnID,
		}
		hasPkg := false
		for j := range vi.Black[i].PKG {
			pg := vi.Black[i].PKG[j]
			hasPkg = true
			vu1 := vu.DeepCopy()
			vu1.PkgName = pg.PkgName
			vu1.PkgVersion = pg.PkgVersion
			res.Black = append(res.Black, vu1)
		}
		if !hasPkg {
			res.Black = append(res.Black, vu)
		}
	}

	return res
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
	HasFixedVuln     bool      `json:"hasFixedVuln"` // 存在可修复漏洞
}

func (vi *VulnDetectRule) ToVulnDetectRuleView() VulnDetectRuleView {
	res := VulnDetectRuleView{
		Enable:           vi.Enable,
		Action:           vi.Action,
		Severity:         vi.Severity,
		Black:            make([]CusVulnView, 0),
		White:            make([]CusVulnView, 0),
		IgnoreUnfixed:    vi.IgnoreUnfixed,
		IgnoreKernelVuln: vi.IgnoreKernelVuln,
		IgnoreLangVuln:   vi.IgnoreLangVuln,
		HasFixedVuln:     vi.HasFixedVuln,
	}

	whiteMap := make(map[string][]CusPkg, 0)
	blackMap := make(map[string][]CusPkg, 0)
	for i := range vi.White {
		wi := vi.White[i]
		if len(whiteMap[wi.VulnID]) == 0 {
			whiteMap[wi.VulnID] = make([]CusPkg, 0)
		}
		if wi.PkgName != "" || wi.PkgVersion != "" {
			whiteMap[wi.VulnID] = append(whiteMap[wi.VulnID], CusPkg{
				PkgName:    wi.PkgName,
				PkgVersion: wi.PkgVersion,
			})
		}
	}
	for i := range vi.Black {
		wi := vi.Black[i]
		if len(blackMap[wi.VulnID]) == 0 {
			blackMap[wi.VulnID] = make([]CusPkg, 0)
		}

		if wi.PkgName != "" || wi.PkgVersion != "" {
			blackMap[wi.VulnID] = append(blackMap[wi.VulnID], CusPkg{
				PkgName:    wi.PkgName,
				PkgVersion: wi.PkgVersion,
			})
		}
	}
	white := make([]CusVulnView, 0)

	for k, v := range whiteMap {
		ww := CusVulnView{
			VulnID: k,
			PKG:    v,
		}
		if len(ww.PKG) == 0 {
			ww.PKG = make([]CusPkg, 0)
		}
		white = append(white, ww)
	}

	black := make([]CusVulnView, 0)

	for k, v := range blackMap {
		ww := CusVulnView{
			VulnID: k,
			PKG:    v,
		}
		if len(ww.PKG) == 0 {
			ww.PKG = make([]CusPkg, 0)
		}
		black = append(black, ww)
	}
	res.White = append(res.White, white...)
	res.Black = append(res.Black, black...)

	return res
}

type CusVuln struct {
	VulnID     string `json:"vulnID"`
	PkgName    string `json:"pkgName"`
	PkgVersion string `json:"pkgVersion"`
}

func (vi *CusVuln) DeepCopy() CusVuln {
	return CusVuln{
		VulnID:     vi.VulnID,
		PkgName:    vi.PkgName,
		PkgVersion: vi.PkgVersion,
	}
}

type CusVulnView struct {
	VulnID string   `json:"vulnID"`
	PKG    []CusPkg `json:"pkg"`
}

type CusPkg struct {
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

type EnableActionRule struct {
	Enable bool   `json:"enable"`
	Action string `json:"action"`
}

type EnvDetectRule struct {
	Enable        bool     `json:"enable"`
	Action        string   `json:"action"`
	CheckPassword bool     `json:"checkPassword"`
	Black         []string `json:"black"`
}

type PolicyScope struct {
	ImageRegexp   []string `json:"imageRegexp"`
	ClusterKey    []string `json:"clusterKey"`
	AllCluster    bool     `json:"allCluster"`
	RegIds        []int64  `json:"regIds"` // 扫描仓库
	AllReg        bool     `json:"allReg"` // 未选仓库时
	ImageFromType string   `json:"imageFromType"`
	ScopeType     string   `json:"scopeType"`
	ClusterName   []string `json:"clusterName"`
	RegName       []string `json:"regName"`
}

func (vi *PolicyScope) Check() error {
	if (vi.ScopeType == DetectScopeTypeImage && len(vi.ImageRegexp) == 0) ||
		(vi.ScopeType == DetectScopeTypeCluster && len(vi.ClusterKey) == 0 && !vi.AllCluster) ||
		(vi.ScopeType == DetectScopeTypeReg && (len(vi.RegIds) == 0 && !vi.AllReg)) {
		return i18.CreateI18BadReqErr("未获取到策略适用范围", "not get policy scope")
	}

	for i := range vi.ImageRegexp {
		reg := vi.ImageRegexp[i]
		if _, err := regexp.Compile(reg); err != nil {
			return i18.CreateI18BadReqErr("镜像正则表达出错", "image scope regexp fail")
		}
	}
	if vi.ScopeType == "" {
		return i18.CreateI18BadReqErr("未获取到策略适用范围", "not get policy scope")
	}
	return nil
}

func (vi *PolicyScope) Same(after PolicyScope) bool {

	if vi.ScopeType != vi.ScopeType {
		return false
	}

	if vi.ScopeType == DetectScopeTypeCluster && vi.AllCluster != after.AllCluster {
		return false
	}

	if vi.ScopeType == DetectScopeTypeReg && vi.AllReg != after.AllReg {
		return false
	}

	if vi.ScopeType == DetectScopeTypeReg {
		for i := range vi.RegIds {
			if !util.ExistInInt64Slice(after.RegIds, vi.RegIds[i]) {
				return false
			}
		}

		for i := range after.RegIds {
			if !util.ExistInInt64Slice(vi.RegIds, after.RegIds[i]) {
				return false
			}
		}
	}
	if vi.ScopeType == DetectScopeTypeCluster {
		for i := range vi.ClusterKey {
			if !util.ExistInStringSlice(after.ClusterKey, vi.ClusterKey[i]) {
				return false
			}
		}

		for i := range after.ClusterKey {
			if !util.ExistInStringSlice(vi.ClusterKey, after.ClusterKey[i]) {
				return false
			}
		}
	}
	if vi.ScopeType == DetectScopeTypeImage {
		for i := range vi.ImageRegexp {
			if !util.ExistInStringSlice(after.ImageRegexp, vi.ImageRegexp[i]) {
				return false
			}
		}

		for i := range after.ImageRegexp {
			if !util.ExistInStringSlice(vi.ImageRegexp, after.ImageRegexp[i]) {
				return false
			}
		}
	}

	return true
}

func (vi *PolicyScope) Serialize() {
	vi.ClusterName = make([]string, 0)
	vi.RegName = make([]string, 0)
}

const (
	DefaultPolicyNameZH = "默认安全策略"
	DefaultPolicyNameEN = "default policy"
)

type SecurityPolicySnapshot struct {
	ID                 int64          `gorm:"primaryKey" json:"id"`
	UniqueID           uint64         `gorm:"column:unique_id" json:"unique_id"`
	PolicyID           int64          `gorm:"column:policy_id"`
	SecurityPolicyJson string         `gorm:"column:security_policy" json:"-"`
	SecurityPolicy     SecurityPolicy `gorm:"-" json:"securityPolicy"`
	CreatedAt          int64          `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
}

func (vi *SecurityPolicySnapshot) TableName() string {
	return "ivan_detect_policy_snapshot"
}

func (vi *SecurityPolicySnapshot) Serialize() {
	bt, _ := json.Marshal(vi.SecurityPolicy)
	vi.SecurityPolicyJson = string(bt)
}

func (vi *SecurityPolicySnapshot) Deserialize() {
	po := SecurityPolicy{}
	if len(vi.SecurityPolicyJson) > 0 {
		if err := json.Unmarshal([]byte(vi.SecurityPolicyJson), &po); err != nil {
			logging.Get().Err(err).Msg("SecurityPolicySnapshot Deserialize")
		} else {
			vi.SecurityPolicy = po
		}
	}
	vi.SecurityPolicy.SetEmptySlice()
}

type SimplePolicy struct {
	ID        int64  `json:"id"`
	IsDefault bool   `json:"isDefault"`
	UniqueID  uint64 `json:"uniqueID,string"`
	Name      string `json:"name"`
	Flag      uint64 `json:"flag,string"` // 保存数据时该镜像在该策略下的结果:现在只用于部署上线
}

func (vi *SimplePolicy) ToPolicy() *SecurityPolicy {
	return &SecurityPolicy{ID: vi.ID, Name: vi.Name, UniqueID: vi.UniqueID, IsDefault: vi.IsDefault}
}

func (vi *SecurityPolicy) ToSimplePolicy() SimplePolicy {
	return SimplePolicy{
		ID:        vi.ID,
		UniqueID:  vi.UniqueID,
		Name:      vi.Name,
		IsDefault: vi.IsDefault,
	}
}

func GetImageFromType(lang string) map[string]string {
	avCH := map[string]string{
		ImageFromNode:     "节点镜像",
		ImageFromRegistry: "仓库镜像",
	}

	avEn := map[string]string{
		ImageFromNode:     "node image",
		ImageFromRegistry: "registry image",
	}
	if lang == model.LangEn {
		return avEn
	}

	return avCH
}

func GetDetectScopeTypeType(lang string) map[string]string {
	avCH := map[string]string{
		DetectScopeTypeReg:     "仓库",
		DetectScopeTypeCluster: "集群",
		DetectScopeTypeImage:   "镜像",
	}

	avEn := map[string]string{
		DetectScopeTypeReg:     "registry",
		DetectScopeTypeCluster: "cluster",
		DetectScopeTypeImage:   "image",
	}
	if lang == model.LangEn {
		return avEn
	}

	return avCH
}

func GetDetectPolicyTypeType(lang string) map[string]string {
	avCH := map[string]string{
		ConfigTypeNodeScanImage: "节点镜像",
		ConfigTypeRegScanImage:  "仓库镜像",
		ConfigTypeDeploy:        "部署上线",
	}

	avEn := map[string]string{
		ConfigTypeNodeScanImage: "node image",
		ConfigTypeRegScanImage:  "registry image",
		ConfigTypeDeploy:        "deployment",
	}
	if lang == model.LangEn {
		return avEn
	}

	return avCH
}
