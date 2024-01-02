package imagesec

import (
	"context"
	"encoding/json"
	"fmt"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageDetectResult struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	DetectType    string `gorm:"-" json:"detectType"`                             // 检测类别，漏洞，敏感文件等
	Flag          uint64 `gorm:"column:flag" json:"flag,string"`                  // 加入的原因等：每一位表示一种方式
	UniqueTarget  uint64 `gorm:"column:unique_target" json:"uniqueTarget,string"` //
	ImageUniqueID uint64 `gorm:"column:image_unique_id" json:"imageUniqueID,string"`
	PolicyID      int64  `gorm:"column:policy_id" json:"policyID"`

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *ImageDetectResult) Same(after *ImageDetectResult) bool {
	if vi.UniqueTarget != after.UniqueTarget || vi.ImageUniqueID != after.ImageUniqueID ||
		vi.PolicyID != after.PolicyID || vi.Flag != after.Flag {
		return false
	}
	return true

}

func (vi *ImageDetectResult) TableName() string {
	if vi == nil {
		return ""
	}

	switch vi.DetectType {
	case DetectTypeVulnRule:
		return "ivan_image_vuln_detect"
	case DetectTypeSensRule:
		return "ivan_image_sensitive_detect"
	case DetectTypeMalwareRule:
		return "ivan_image_malware_detect"
	case DetectTypePkgRule:
		return "ivan_image_pkg_detect"
	case DetectTypeLicenseRule:
		return "ivan_image_license_detect"
	case DetectTypeWebshellRule:
		return "ivan_image_webshell_detect"
	case DetectTypeRootRule:
		return "ivan_image_root_detect"
	case DetectTypeEnvRule:
		return "ivan_image_env_detect"
	case DetectTypeBaseImageRule:
		return "ivan_image_base_detect"
	case DetectTypeTrustedImageRule:
		return "ivan_image_trusted_detect"
	case DetectTypeExistInRegRule:
		return "ivan_image_exist_reg_detect"
	}
	return ""
}

type ImageDetectType string

func (vi ImageDetectType) String() string {
	return string(vi)
}

func (vi ImageDetectType) Check() error {
	if !util.ExistInStringSlice(GetDetectTypes(), vi.String()) {
		return fmt.Errorf("ImageDetectType is not right :%s", vi.String())
	}
	return nil
}

const (
	DetectTypeVulnRule         = "vuln-rule"
	DetectTypeSensRule         = "sens-rule"
	DetectTypeMalwareRule      = "malware-rule"
	DetectTypePkgRule          = "pkg-rule"
	DetectTypeLicenseRule      = "license-rule"
	DetectTypeWebshellRule     = "webshell-rule"
	DetectTypeRootRule         = "root-rule"
	DetectTypeEnvRule          = "env-rule"
	DetectTypeExistInRegRule   = "exist-in-reg"
	DetectTypeBaseImageRule    = "base-image-rule"
	DetectTypeTrustedImageRule = "trusted-image-rule"

	// 部署上线特有
	DetectTypeImageExit    = "image-exit"
	DetectTypeImageScanned = "image-scanned"
	DetectTypeImageHasErr  = "has-error"
)

func GetDetectTypes() []string {
	return []string{
		DetectTypeVulnRule,
		DetectTypeSensRule,
		DetectTypeMalwareRule,
		DetectTypePkgRule,
		DetectTypeWebshellRule,
		DetectTypeRootRule,
		DetectTypeEnvRule,
		DetectTypeExistInRegRule,
		DetectTypeBaseImageRule,
		DetectTypeTrustedImageRule,
	}
}

type PolicyDetect struct {
	InWhite             bool   `json:"inWhite"`
	Exception           bool   `json:"exception"`
	ExceptionPkgLicense bool   `json:"exceptionPkgLicense"` // 只针对软件的License
	PasswdEnv           bool   `json:"passwdEnv"`           // 包含密码的 ENV
	DeployAction        string `json:"deployAction"`
}

const (
	FlagDetectException = 1
	// 差一个，以后补上
	FlagDetectInWhite              = 3
	FlagDetectEnvHasPasswd         = 4
	FlagDetectVulnSeverityCritical = 5
	FlagDetectVulnSeverityHigh     = 6
	FlagDetectVulnSeverityMedium   = 7
	FlagDetectVulnSeverityLow      = 8
	FlagDetectVulnSeverityKnown    = 9
	FlagDetectExceptionPkgLicense  = 10
	FlagDetectDeployActionBlock    = 11 // 阻断
	FlagDetectDeployActionAlarm    = 12 // 报警
)

func (vi *PolicyDetect) GenPolicyDetect(flag uint64) {
	if vi.Exception || vi.ExceptionPkgLicense {
		if util.ExistBit1(flag, FlagDetectExceptionPkgLicense) {
			// TODO 这一期 异常软件和异常开源协议分开算，下一期整合
			// vi.Exception = true
			vi.ExceptionPkgLicense = true
		}
		if util.ExistBit1(flag, FlagDetectException) {
			vi.Exception = true
		}
		return
	}

	if util.ExistBit1(flag, FlagDetectException) {
		vi.Exception = true
	}
	if util.ExistBit1(flag, FlagDetectEnvHasPasswd) {
		vi.Exception = true
		vi.PasswdEnv = true
	}

	if util.ExistBit1(flag, FlagDetectExceptionPkgLicense) {
		// TODO 这一期 异常软件和异常开源协议分开算，下一期整合
		// vi.Exception = true
		vi.ExceptionPkgLicense = true
	}

	if util.ExistBit1(flag, FlagDetectDeployActionBlock) {
		vi.DeployAction = DeployActionBlock
	}
	if util.ExistBit1(flag, FlagDetectDeployActionAlarm) {
		vi.DeployAction = DeployActionAlarm
	}

	// 当前的白名单
	if util.ExistBit1(flag, FlagDetectInWhite) {
		vi.InWhite = true
		vi.Exception = false
		vi.PasswdEnv = false
		vi.ExceptionPkgLicense = false
		vi.DeployAction = DeployActionPass
	}
	// 白名单只对自已策略有效
	// 所有策略的并集，如果一个策略检测出是风险，那么即使另一个策略加了白名单，也是风险的
	// 如果检测到异常,把之前策略的白名单失效
	if !util.ExistBit1(flag, FlagDetectInWhite) && (util.ExistBit1(flag, FlagDetectException) ||
		util.ExistBit1(flag, FlagDetectExceptionPkgLicense)) {
		vi.InWhite = false // 白名单只影响当前策略
	}
}

func (vi *PolicyDetect) AddPolicyDetect(uid uint64, ds []*ImageDetectResult) {
	if vi == nil || len(ds) == 0 {
		return
	}

	for i := range ds {
		d := ds[i]
		if uid != d.UniqueTarget {
			continue
		}
		vi.GenPolicyDetect(d.Flag)
	}
}

// 注意：白名单只影响当前策略，不影响其他策略
func (vi *PolicyDetect) AddDeployDetect(uid uint64, ds []DeployIssue) {
	if vi.DeployAction == "" {
		vi.DeployAction = DeployActionPass
	}

	if vi == nil || len(ds) == 0 {
		return
	}

	for i := range ds {
		d := ds[i]
		if uid != d.Target {
			continue
		}
		vi.GenPolicyDetect(d.Flag)
		break
	}
}

func GetVulnSeverityDetectFlag(severity int64) uint64 {
	switch severity {
	case SeverityCriticalInt:
		return FlagDetectVulnSeverityCritical
	case SeverityHighInt:
		return FlagDetectVulnSeverityHigh
	case SeverityMediumInt:
		return FlagDetectVulnSeverityMedium
	case SeverityLowInt:
		return FlagDetectVulnSeverityLow
	case SeverityUnknownInt:
		return FlagDetectVulnSeverityKnown
	default:
		return 0
	}
}

func (vi *ImageDetectResult) ToPolicyDetect() PolicyDetect {
	ans := PolicyDetect{}
	if util.ExistBit1(vi.Flag, FlagDetectInWhite) {
		ans.InWhite = true
		// 白名单优先级最高
		return ans
	}
	if util.ExistBit1(vi.Flag, FlagDetectException) {
		ans.Exception = true
	}

	return ans
}

// 按策略对镜像的检测结果(简略，只是标记是否安全)
type ImageDetectBrief struct {
	ID             int64  `gorm:"primaryKey" json:"id"`
	ImageUniqueID  uint64 `gorm:"column:image_unique_id" json:"imageUniqueID,string"`
	PolicyID       int64  `gorm:"column:policy_id" json:"policyID"`
	PolicyUniqueID uint64 `gorm:"column:policy_unique_id" json:"policyUniqueID,string"` // 主要是为了保存快照
	Flag           uint64 `gorm:"column:flag" json:"flag,string"`                       // 检测结果
	// 2.20之前全量保存了策略数据，2.20之后进行了优化，只是保存了SimplePolicy
	PolicyJson   string          `gorm:"column:policy" json:"-"`
	SimplePolicy *SimplePolicy   `gorm:"-" json:"simplePolicy"` // 数据库的结
	Policy       *SecurityPolicy `gorm:"-" json:"policy"`       // 查询用

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *ImageDetectBrief) TableName() string {
	if vi == nil {
		return ""
	}
	return "ivan_image_detect_brief"
}

func (vi *ImageDetectBrief) ChangePolicyName(ctx context.Context) *ImageDetectBrief {
	if vi == nil {
		return nil
	}

	po := vi.Policy
	po2 := vi.SimplePolicy

	la, ok := ctx.Value(AcceptLanguage).(string)

	if ok && la == LangZh && po != nil && (po.IsDefault || po.Name == DefaultPolicyNameEN) {
		po.Name = DefaultPolicyNameZH
	}
	vi.Policy = po

	if ok && la == LangZh && po2 != nil && (po2.IsDefault || po2.Name == DefaultPolicyNameEN) {
		po2.Name = DefaultPolicyNameZH
	}
	vi.SimplePolicy = po2

	return vi
}

func (vi *ImageDetectBrief) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.ImageUniqueID <= 0 {
		return fmt.Errorf("not get ImageID")
	}
	if vi.PolicyID <= 0 {
		return fmt.Errorf("not get PolicyID")
	}
	return nil
}

func (vi *ImageDetectBrief) Same(after *ImageDetectBrief) bool {
	if vi.ImageUniqueID != after.ImageUniqueID || vi.PolicyID != after.PolicyID || vi.Flag != after.Flag ||
		vi.PolicyUniqueID != after.PolicyUniqueID {
		return false
	}
	return true
}

func (vi *ImageDetectBrief) Deserialize() {
	if vi.PolicyJson != "" {
		po := &SimplePolicy{}
		if err := json.Unmarshal([]byte(vi.PolicyJson), po); err == nil {
			vi.SimplePolicy = po
		}
		// 2.20版本
		if vi.Policy == nil {
			po2 := &SecurityPolicy{}
			if err := json.Unmarshal([]byte(vi.PolicyJson), po2); err == nil {
				vi.Policy = po2
			}
		}
	}
	if vi.Policy != nil && vi.SimplePolicy == nil {
		vi.SimplePolicy = &SimplePolicy{
			ID:        vi.Policy.ID,
			UniqueID:  vi.Policy.UniqueID,
			IsDefault: vi.Policy.IsDefault,
			Name:      vi.Policy.Name,
		}
	}
}

func (vi *ImageDetectBrief) Serialize() {
	if vi.SimplePolicy == nil && vi.Policy != nil {
		vi.SimplePolicy = &SimplePolicy{
			ID:        vi.Policy.ID,
			IsDefault: vi.Policy.IsDefault,
			UniqueID:  vi.Policy.UniqueID,
			Name:      vi.Policy.Name,
		}
	}

	if vi.SimplePolicy != nil {
		vi.PolicyUniqueID = vi.SimplePolicy.UniqueID
		vi.PolicyID = vi.SimplePolicy.ID
		if vi.SimplePolicy.Flag <= 0 {
			vi.SimplePolicy.Flag = vi.Flag
		}

		if bys, err := json.Marshal(vi.SimplePolicy); err == nil {
			vi.PolicyJson = string(bys)
		}
	}
}

func AddImageSafeFlag(vi []*ImageDetectBrief, preFlag uint64) uint64 {
	// 能这样判断是有以下两个条件：
	// 1: 默认检测策略 包括全部集群（也就是包括全部镜像）
	// 2，默认策略是开启的，且不可以关闭
	// 如果之后需要有变动，则需要相应的变动
	if len(vi) == 0 {
		preFlag = util.SetBit0(util.SetBit0(util.SetBit1(preFlag, FlagImageSafeUnknown), FlagImageUnsafe), FlagImageSafe)
		return preFlag
	}

	safe := true
	for i := range vi {
		if util.ExistBit1(vi[i].Flag, FlagDetectException) {
			safe = false
			break
		}
	}
	if safe {
		preFlag = util.SetBit0(util.SetBit0(util.SetBit1(preFlag, FlagImageSafe), FlagImageUnsafe), FlagImageSafeUnknown)
	} else {
		preFlag = util.SetBit0(util.SetBit0(util.SetBit1(preFlag, FlagImageUnsafe), FlagImageSafe), FlagImageSafeUnknown)
	}
	logging.Get().Debug().Bool("safe", safe).Msg("AddImageSafeFlag")
	return preFlag
}
