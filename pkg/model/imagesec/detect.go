package imagesec

import (
	"encoding/json"
	"fmt"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
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
	case DetectTypePkgVersionRule:
		return "ivan_image_pkg_detect"
	case DetectTypePkgLicenseRule:
		return "ivan_image_license_detect"
	case DetectTypeWebshellRule:
		return "ivan_image_webshell_detect"
	case DetectTypeRootRule:
		return "ivan_image_root_detect"
	case DetectTypeEnvRule:
		return "ivan_image_env_detect"
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
	DetectTypeVulnRule       = "vuln-rule"
	DetectTypeSensRule       = "sens-rule"
	DetectTypeMalwareRule    = "malware-rule"
	DetectTypePkgVersionRule = "pkg-rule"
	DetectTypePkgLicenseRule = "pkg-license-rule"
	DetectTypeWebshellRule   = "webshell-rule"
	DetectTypeRootRule       = "root-rule"
	DetectTypeEnvRule        = "env-rule"
)

func GetDetectTypes() []string {
	return []string{
		DetectTypeVulnRule,
		DetectTypeSensRule,
		DetectTypeMalwareRule,
		DetectTypePkgVersionRule,
		DetectTypePkgLicenseRule,
		DetectTypeWebshellRule,
		DetectTypeRootRule,
		DetectTypeEnvRule,
	}
}

type PolicyDetect struct {
	InBlack          bool `json:"inBlack"`
	InWhite          bool `json:"inWhite"`
	Exception        bool `json:"exception"`
	ExceptionLicense bool `json:"exceptionLicense"` // 只针对软件
	PasswdEnv        bool `json:"passwdEnv"`        // 包含密码的 ENV
}

const (
	FlagDetectException            = 1
	FlagDetectInBlack              = 2
	FlagDetectInWhite              = 3
	FlagDetectEnvHasPasswd         = 4
	FlagDetectVulnSeverityCritical = 5
	FlagDetectVulnSeverityHigh     = 6
	FlagDetectVulnSeverityMedium   = 7
	FlagDetectVulnSeverityLow      = 8
	FlagDetectVulnSeverityKnown    = 9
)

func (vi *PolicyDetect) AddPolicyDetect(uid uint64, ds []*ImageDetectResult) {
	if vi == nil || len(ds) == 0 {
		return
	}

	for i := range ds {
		d := ds[i]
		if uid != d.UniqueTarget {
			continue
		}
		// 白名单优先级最高
		if vi.InWhite || util.ExistBit1(d.Flag, FlagDetectInWhite) {
			vi.InWhite = true
			vi.Exception = false
			vi.InBlack = false
			vi.PasswdEnv = false
			vi.ExceptionLicense = false
			return
		}
		if util.ExistBit1(d.Flag, FlagDetectException) {
			vi.Exception = true
		}
		if util.ExistBit1(d.Flag, FlagDetectInBlack) {
			vi.InBlack = true
			vi.Exception = true
		}
		if util.ExistBit1(d.Flag, FlagDetectEnvHasPasswd) {
			vi.Exception = true
			vi.PasswdEnv = true
		}

		if util.ExistBit1(d.Flag, FlagDetectException) {
			vi.Exception = true
			vi.ExceptionLicense = true
		}
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
	if util.ExistBit1(vi.Flag, FlagDetectInBlack) {
		ans.InBlack = true
		ans.Exception = true
	}

	return ans
}

// 按策略对镜像的检测结果(简略，只是标记是否安全)
type ImageDetectBrief struct {
	ID            int64           `gorm:"primaryKey" json:"id"`
	ImageUniqueID uint64          `gorm:"column:image_unique_id" json:"imageUniqueID,string"`
	PolicyID      int64           `gorm:"column:policy_id" json:"policyID"`
	Flag          uint64          `gorm:"column:flag" json:"flag"`
	PolicyJson    string          `gorm:"column:policy" json:"-"`
	Policy        *SecurityPolicy `gorm:"-" json:"policy"`

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *ImageDetectBrief) TableName() string {
	if vi == nil {
		return ""
	}
	return "ivan_image_detect_brief"
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
	if vi.ImageUniqueID != after.ImageUniqueID || vi.PolicyID != after.PolicyID || vi.Flag != vi.Flag || vi.PolicyJson != after.PolicyJson {
		return false
	}
	return true
}

func (vi *ImageDetectBrief) Deserialize() {
	po := SecurityPolicy{}

	if vi.PolicyJson != "" {
		if err := json.Unmarshal([]byte(vi.PolicyJson), &po); err == nil {
			vi.Policy = &po
		}
	}
}

func (vi *ImageDetectBrief) Serialize() {
	if vi.Policy != nil {
		if bys, err := json.Marshal(vi.Policy); err == nil {
			vi.PolicyJson = string(bys)
		}
	}
}

type ImageDetectBriefResult []*ImageDetectBrief

func AddImageSafeFlag(vi []*ImageDetectBrief, preFlag uint64) uint64 {
	safe := true

	for i := range vi {
		if util.ExistBit1(vi[i].Flag, FlagDetectException) {
			safe = false
			break
		}
	}
	if safe {
		preFlag = util.SetBit0(util.SetBit0(util.SetBit1(preFlag, model.FlagImageSafe), model.FlagImageUnsafe), model.FlagImageSafeUnknown)
	} else {
		preFlag = util.SetBit0(util.SetBit0(util.SetBit1(preFlag, model.FlagImageUnsafe), model.FlagImageSafe), model.FlagImageSafeUnknown)
	}
	logging.Get().Debug().Bool("safe", safe).Msg("AddImageSafeFlag")
	return preFlag
}
