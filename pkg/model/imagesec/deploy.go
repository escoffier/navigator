package imagesec

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type DeployRecord struct {
	ID                 int64          `gorm:"column:id" json:"id"`
	ImageUUID          uint32         `gorm:"column:image_uuid" json:"imageUUID"`
	ImageUniqueID      uint64         `gorm:"column:image_unique_id" json:"imageUniqueID,string"`
	ImageName          string         `gorm:"column:image_name" json:"imageName"`
	Host               string         `gorm:"column:host" json:"host"`
	Repo               string         `gorm:"column:repo" json:"repo"`
	Tag                string         `gorm:"column:tag" json:"tag"`
	Image              Image          `gorm:"-"  json:"image"`
	ImageJson          string         `gorm:"column:image" json:"-"`
	Digest             string         `gorm:"column:digest" json:"digest"`
	Action             string         `gorm:"column:action" json:"action"`
	Flag               uint64         `gorm:"column:flag" json:"flag,string"`
	VulnJSON           string         `gorm:"column:vuln" json:"-"`
	Vuln               []uint64       `gorm:"-" json:"vuln"`
	VulnIssue          []DeployIssue  `gorm:"-" json:"vulnIssue"`
	MalwareJSON        string         `gorm:"column:malware" json:"-"`
	Malware            []uint64       `gorm:"-" json:"malware"`
	MalwareIssue       []DeployIssue  `gorm:"-" json:"malwareIssue"`
	WebshellJSON       string         `gorm:"column:webshell" json:"-"`
	Webshell           []uint64       `gorm:"-" json:"webshell"`
	WebshellIssue      []DeployIssue  `gorm:"-" json:"webshellIssue"`
	SensitiveJSON      string         `gorm:"column:sensitive" json:"-"`
	Sensitive          []uint64       `gorm:"-" json:"sensitive"`
	SensitiveIssue     []DeployIssue  `gorm:"-" json:"sensitiveIssue"`
	PkgJSON            string         `gorm:"column:pkg" json:"-"`
	Pkg                []uint64       `gorm:"-" json:"pkg"`
	PkgIssue           []DeployIssue  `gorm:"-" json:"pkgIssue"`
	LicenseJSON        string         `gorm:"column:license" json:"-"`
	License            []uint64       `gorm:"-" json:"license"`      // license 文件
	LicenseIssue       []DeployIssue  `gorm:"-" json:"licenseIssue"` // license 文件
	EnvJSON            string         `gorm:"column:env" json:"-"`
	Env                []uint64       `gorm:"-" json:"env"`
	EnvIssue           []DeployIssue  `gorm:"-" json:"envIssue"`
	RootBootJSON       string         `gorm:"column:root_boot" json:"-"`
	RootBootIssue      []DeployIssue  `gorm:"-" json:"rootBootIssue"`
	BaseImageJSON      string         `gorm:"column:base_image" json:"-"`
	BaseImage          bool           `gorm:"-" json:"baseImage"`
	BaseImageIssue     []DeployIssue  `gorm:"-" json:"baseImageIssue"`
	TrustedImageJSON   string         `gorm:"column:trusted_image" json:"-"`
	TrustedImageIssue  []DeployIssue  `gorm:"-" json:"trustedImageIssue"`
	RiskPolicyJson     string         `gorm:"column:risk_policy" json:"-"`
	TotalPolicyJson    string         `gorm:"column:total_policy" json:"-"`
	RiskPolicy         []SimplePolicy `gorm:"-" json:"riskPolicy"`
	TotalPolicy        []SimplePolicy `gorm:"-" json:"totalPolicy"`
	PolicyUniqueIDJson string         `gorm:"column:policy_unique_id" json:"-"`
	Hour               int64          `gorm:"column:hour" json:"hour"`
	Day                int64          `gorm:"column:day" json:"day"`

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds

}

func (vi *DeployRecord) TableName() string {
	return "ivan_scan_deploy_record"
}

type DeployIssue struct {
	Target uint64 `json:"target,string"`
	Action string `json:"action"`
	Flag   uint64 `json:"flag,string"`
}

func (vi *DeployRecord) GetDeployAction() string {

	if util.ExistBit1(vi.Flag, FlagImageDeployBlock) {
		return DeployActionBlock
	}
	if util.ExistBit1(vi.Flag, FlagImageDeployAlarm) {
		return DeployActionAlarm
	}
	return DeployActionPass
}

func (vi *DeployRecord) Deserialize() {
	_ = json.Unmarshal([]byte(vi.VulnJSON), &vi.VulnIssue)
	_ = json.Unmarshal([]byte(vi.ImageJson), &vi.Image)
	_ = json.Unmarshal([]byte(vi.MalwareJSON), &vi.MalwareIssue)
	_ = json.Unmarshal([]byte(vi.WebshellJSON), &vi.WebshellIssue)
	_ = json.Unmarshal([]byte(vi.SensitiveJSON), &vi.SensitiveIssue)
	_ = json.Unmarshal([]byte(vi.LicenseJSON), &vi.LicenseIssue)
	_ = json.Unmarshal([]byte(vi.EnvJSON), &vi.EnvIssue)
	_ = json.Unmarshal([]byte(vi.PkgJSON), &vi.PkgIssue)
	_ = json.Unmarshal([]byte(vi.RiskPolicyJson), &vi.RiskPolicy)
	_ = json.Unmarshal([]byte(vi.TotalPolicyJson), &vi.TotalPolicy)

	vi.Vuln = vi.GetTarget(vi.VulnIssue)
	vi.Malware = vi.GetTarget(vi.MalwareIssue)
	vi.Webshell = vi.GetTarget(vi.WebshellIssue)
	vi.Sensitive = vi.GetTarget(vi.SensitiveIssue)
	vi.Pkg = vi.GetTarget(vi.PkgIssue)
	vi.License = vi.GetTarget(vi.LicenseIssue)
	vi.Env = vi.GetTarget(vi.EnvIssue)
}

func (vi *DeployRecord) Serialize() {
	vi.VulnIssue = DeduplicateDeployIssue(vi.VulnIssue)
	vi.MalwareIssue = DeduplicateDeployIssue(vi.MalwareIssue)
	vi.WebshellIssue = DeduplicateDeployIssue(vi.WebshellIssue)
	vi.SensitiveIssue = DeduplicateDeployIssue(vi.SensitiveIssue)
	vi.PkgIssue = DeduplicateDeployIssue(vi.PkgIssue)
	vi.LicenseIssue = DeduplicateDeployIssue(vi.LicenseIssue)
	vi.EnvIssue = DeduplicateDeployIssue(vi.EnvIssue)
	vi.BaseImageIssue = DeduplicateDeployIssue(vi.BaseImageIssue)
	vi.TrustedImageIssue = DeduplicateDeployIssue(vi.TrustedImageIssue)

	vi.VulnJSON = vi.MarshalDeployIssue(vi.VulnIssue)
	vi.MalwareJSON = vi.MarshalDeployIssue(vi.MalwareIssue)
	vi.WebshellJSON = vi.MarshalDeployIssue(vi.WebshellIssue)
	vi.SensitiveJSON = vi.MarshalDeployIssue(vi.SensitiveIssue)
	vi.PkgJSON = vi.MarshalDeployIssue(vi.PkgIssue)
	vi.LicenseJSON = vi.MarshalDeployIssue(vi.LicenseIssue)
	vi.EnvJSON = vi.MarshalDeployIssue(vi.EnvIssue)
	vi.BaseImageJSON = vi.MarshalDeployIssue(vi.BaseImageIssue)
	vi.TrustedImageJSON = vi.MarshalDeployIssue(vi.TrustedImageIssue)

	policyUniqueID := make([]string, 0)

	for i := range vi.RiskPolicy {
		policyUniqueID = append(policyUniqueID, fmt.Sprintf("%d", vi.RiskPolicy[i].UniqueID))
	}

	vi.PolicyUniqueIDJson = strings.Join(policyUniqueID, ",")

	if pn, err := json.Marshal(vi.RiskPolicy); err == nil {
		vi.RiskPolicyJson = string(pn)
	}

	if pn, err := json.Marshal(vi.TotalPolicy); err == nil {
		vi.TotalPolicyJson = string(pn)
	}
	if pn, err := json.Marshal(vi.Image); err == nil {
		vi.ImageJson = string(pn)
	}

	if vi.Day <= 0 {
		vi.Day = util.DaySinceUnixEpoch(time.Now().UTC())
	}
	if vi.Hour <= 0 {
		vi.Hour = util.HourSinceUnixEpoch(time.Now().UTC())
	}

	vi.SetActionFlag()
}

func (vi *DeployRecord) MarshalDeployIssue(sr []DeployIssue) string {
	for i := range sr {
		if util.ExistBit1(sr[i].Flag, FlagDetectDeployActionBlock) {
			sr[i].Action = DeployActionBlock
		}
		if util.ExistBit1(sr[i].Flag, FlagDetectDeployActionAlarm) {
			sr[i].Action = DeployActionAlarm
		}
	}

	bys, err := json.Marshal(sr)
	if err != nil {
		return ""
	}
	return string(bys)
}

func (vi *DeployRecord) GetTarget(ta []DeployIssue) []uint64 {
	ans := make([]uint64, 0)
	for i := range ta {
		ans = append(ans, ta[i].Target)
	}
	return ans
}

func (vi *DeployRecord) SetActionFlag() {
	switch vi.Action {
	case DeployActionBlock:
		vi.Flag = util.SetBit1(vi.Flag, FlagImageDeployBlock)
	case DeployActionAlarm:
		vi.Flag = util.SetBit1(vi.Flag, FlagImageDeployAlarm)
	case DeployActionPass:
		vi.Flag = util.SetBit1(vi.Flag, FlagImageDeployPassed)
	}
}

type DeployWhiteImage struct {
	ID        int64  `gorm:"column:id" json:"id"`
	ImageName string `gorm:"column:image_name" json:"imageName"`

	Creator      string `gorm:"column:creator" json:"creator"` // 创建人
	Updater      string `gorm:"column:updater" json:"updater"`
	ExpirationAt int64  `gorm:"column:expiration_at" json:"expirationAt"`

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *DeployWhiteImage) TableName() string {
	return "ivan_scan_deploy_white_image"
}

func (vi *DeployWhiteImage) ToUpdater() map[string]interface{} {
	update := map[string]interface{}{
		// "image_name":    vi.ImageName, // 暂时不可以编辑
		"creator":       vi.CreatedAt,
		"updater":       vi.UpdatedAt,
		"expiration_at": vi.ExpirationAt,
		"updated_at":    time.Now().UnixMilli(),
	}
	return update
}

func (vi *DeployWhiteImage) Check() error {
	if vi.ImageName == "" {
		return i18.CreateI18BadReqErr("未获取到镜像名", "not get image name")
	}
	_, err := regexp.Compile(vi.ImageName)
	if err != nil {
		return i18.CreateI18BadReqErr("未获取到镜像名", "not get image name")
	}
	if vi.ExpirationAt < time.Now().UnixMilli() {
		return i18.CreateI18BadReqErr("有效期设置错误", "expiration incorrect")
	}
	return nil
}

type DeployMonitorImage struct {
	Image         string              `json:"image"`
	Repo          string              `json:"repo"`
	Host          string              `json:"host"`
	Tag           string              `json:"tag"`
	Digest        string              `json:"digest"`
	FromType      string              `json:"type"`
	NotifyContext model.NotifyContext `json:"notify_context"`
	ImageUUID     uint32              `json:"imageUUID"`
}

func (vi *DeployMonitorImage) Empty() bool {
	if vi.Image == "" {
		return true
	}
	return false
}

func (vi *DeployMonitorImage) GenImageUUID() uint32 {
	imageName := vi.Image
	imageName = strings.ReplaceAll(imageName, "https://", "")
	imageName = strings.ReplaceAll(imageName, "http://", "")
	imageName = fmt.Sprintf("%s@%s", imageName, vi.Digest)
	uuid := util.GenerateUUID(imageName)
	vi.ImageUUID = uuid
	return uuid
}

type ImageDataForDeployRes struct {
	MonitorImage  DeployMonitorImage
	Exit          bool
	Scanned       bool
	Errs          []error
	CorrelateData *ImageWithCorrelateData2
	Action        string
	Safe          bool
}

func DeduplicateDeployIssue(issue []DeployIssue) []DeployIssue {
	res := make([]DeployIssue, 0)
	exit := make(map[uint64]bool)
	for i := range issue {
		if !exit[issue[i].Target] {
			res = append(res, issue[i])
			exit[issue[i].Target] = true
		}

	}
	return res
}

type DeployTrend struct {
	Day7   int64 `json:"day7"`
	Day30  int64 `json:"day30"`
	Hour24 int64 `json:"hour24"`
}

type DeployOverview struct {
	Day7   []ActionOverview `json:"day7"`
	Day30  []ActionOverview `json:"day30"`
	Hour24 []ActionOverview `json:"hour24"`
	Trend  DeployTrend      `json:"trend"`
}

type ActionGroup struct {
	Block int64 `json:"block"`
	Alarm int64 `json:"alarm"`
	Pass  int64 `json:"pass"`
}

type ActionOverview struct {
	Total  int64       `json:"total"`
	TimeAt int64       `json:"timeAt"`
	Group  ActionGroup `json:"group"`
}

func (vi *ActionOverview) AdaptTimeZone() {
	vi.TimeAt = vi.TimeAt - 8*60*60*1000
}

type ActionOverviews []*ActionOverview

func (vi ActionOverviews) Len() int {
	return len(vi)
}

func (vi ActionOverviews) Less(i, j int) bool {
	return vi[i].TimeAt < vi[j].TimeAt
}

func (vi ActionOverviews) Swap(i, j int) {
	vi[i], vi[j] = vi[j], vi[i]
}

type ReasonOverview struct {
	Reason string `json:"reason"`
	Count  int64  `json:"count"`
}

type GroupDeployFlagParam struct {
	Day7      string
	Day30     string
	Hour24    string
	Day       string
	Hour      string
	StartDay  int64
	EndDay    int64
	StartHour int64
	EndHour   int64
	Reason    string
}

func (vi *GroupDeployFlagParam) Serialize() {
	if vi.Day7 == TrueString {
		vi.Day = TrueString
		vi.StartDay = util.DaySinceUnixEpoch(time.Now()) - 7
	}
	if vi.Day30 == TrueString {
		vi.Day = TrueString
		vi.StartDay = util.DaySinceUnixEpoch(time.Now()) - 30
	}
	if vi.Hour24 == TrueString {
		vi.Hour = TrueString
		vi.StartHour = util.HourSinceUnixEpoch(time.Now()) - 24
	}
	if vi.Reason == TrueString {
		vi.StartDay = util.DaySinceUnixEpoch(time.Now()) - 30
	}
}

type DeployFlagGroup struct {
	Flag  uint64 `gorm:"column:flag" json:"flag"`
	Day   int64  `gorm:"column:day" json:"day"`
	Hour  int64  `gorm:"column:hour" json:"hour"`
	Count int64  `gorm:"column:cnt" json:"count"`
}

type DeployRecordView struct {
	ID            int64                   `json:"id"`
	ImageUUID     uint32                  `json:"imageUUID"`
	ImageName     string                  `json:"imageName"`
	Digest        string                  `json:"digest"`
	Action        string                  `json:"action"`
	White         bool                    `json:"white"`   // 是否白名单
	InWhite       bool                    `json:"inWhite"` // 是否在白名单名
	Flag          uint64                  `json:"flag"`
	ImageFromType string                  `json:"imageFromType"`
	ImageUniqueID uint64                  `json:"imageUniqueID,string"`
	SecurityIssue []SecurityIssueLabel    `json:"securityIssue"` // 安全问题
	VulnStatic    ImageVulnSeverityStatic `json:"vulnStatic"`
	RiskPolicy    []SimplePolicy          `json:"riskPolicy"`   // 镜像的风险来源
	TotalPolicy   []SimplePolicy          `json:"totalPolicy"`  // 镜像的风险来源
	FullRepoName  string                  `json:"fullRepoName"` // 以下是为了和镜像列表保持一致，便于前端统一
	Tag           string                  `json:"tag"`
	LastScanAt    int64                   `json:"lastScanAt"` // 扫描完成时间戳(单位毫秒)
	RegistryUrl   string                  `json:"registryUrl"`
	CreatedAt     int64                   `json:"createdAt"` // milliseconds
	UpdatedAt     int64                   `json:"updatedAt"` // milliseconds

	DeployRecord *DeployRecord `json:"-"`
}

func (vi *DeployRecordView) FullNull() {
	if len(vi.RiskPolicy) == 0 {
		vi.RiskPolicy = make([]SimplePolicy, 0)
	}
	if len(vi.SecurityIssue) == 0 {
		vi.SecurityIssue = make([]SecurityIssueLabel, 0)
	}
}

func GenDeployRecordView(base *ImageBaseResponse, rec *DeployRecord) DeployRecordView {
	view := DeployRecordView{
		ID:            rec.ID,
		ImageUUID:     rec.ImageUUID,
		ImageName:     rec.ImageName,
		Action:        rec.Action,
		White:         false,
		Flag:          rec.Flag,
		ImageFromType: ImageFromDeploy,
		ImageUniqueID: rec.ImageUniqueID,
		SecurityIssue: base.SecurityIssue,
		VulnStatic:    base.VulnStatic,
		RiskPolicy:    rec.RiskPolicy,
		TotalPolicy:   rec.TotalPolicy,
		Digest:        rec.Digest,
		FullRepoName:  rec.Repo,
		Tag:           rec.Tag,
		RegistryUrl:   rec.Host,
		CreatedAt:     rec.CreatedAt,
		UpdatedAt:     rec.UpdatedAt,
		DeployRecord:  rec,
		InWhite:       false,
	}
	if util.ExistBit1(rec.Flag, FlagImageDeployWhite) {
		view.White = true
	}
	if base != nil {
		view.SecurityIssue = base.SecurityIssue
		view.VulnStatic = base.VulnStatic
	}

	return view
}

type DeploySearchApiParam struct {
	ImageFromType          string             `json:"imageFromType"`
	ImageKeyword           string             `json:"imageKeyword"`
	RegKeyword             string             `json:"regKeyword"`
	PolicyUniqueID         []uint64           `json:"policyUniqueID"`
	PolicyIntersection     string             `json:"policyIntersection"`
	SecurityIssue          []string           `json:"securityIssue"`   // 安全问题,镜像属性也放在这里
	RegIds                 []int64            `json:"regIds"`          // 仓库ID
	ImageAttrView          []string           `json:"imageAttr"`       // 镜像属性,前端以列表的方式传递
	SafeAttr               []string           `json:"safeAttr"`        // safe，unsafe,unknown
	VulnStatic             []string           `json:"vulnStatic"`      // 镜像漏洞统计
	ImageIds               []int64            `json:"imageIds"`        // 镜像ID列表
	ImageID                int64              `json:"imageID"`         // 镜像ID
	ScanStatus             []string           `json:"scanStatus"`      // 扫描状态
	JustReturnImage        bool               `json:"justReturnImage"` // 只需要镜像信息，不需要镜像关联信息
	ReturnMalicious        bool               `json:"returnMalicious"` // 是否返回恶义文件
	UUIDs                  []uint32           `json:"uuids"`           // 镜像uuid
	UniqueIds              []uint64           `json:"uniqueIds"`
	UniqueId               uint64             `json:"uniqueId,string"`
	Projects               []string           `json:"projects"`               // 仓库和repo的筛选
	AttrIntersection       string             `json:"attrIntersection"`       // 属性交集还是并集 and or
	IssueIntersection      string             `json:"issueIntersection"`      // 安全问题交集还是并集 and or
	VulnStaticIntersection string             `json:"vulnStaticIntersection"` // 漏洞统计交集还是并集 and or
	NotIdentifyOnline      bool               `json:"notIdentifyOnline"`      // 是否识别是在线还是离线 默认需要识别
	NotIdentifyTrusted     bool               `json:"notIdentifyTrusted"`     // 是否识别是可信镜像 默认需要识别
	StartID                int64              `json:"startID"`                // 分页请求时，上一页最后一条数据的ID
	ImageScanTaskInfo      CreateScanTaskInfo `json:"imageScanTaskInfo"`
	ClusterKey             []string           `json:"clusterKey"`
	WebshellMD5            string             `json:"webshellMd5"`
	MalwareMD5             string             `json:"malwareMD5"`
	SensitiveMD5           string             `json:"sensitiveMD5"`
	DeployAction           []string           `json:"deployAction"` // 部署上线特有
	Filter                 *model.Filter
}

func GetDeployAction(lang string) map[string]string {
	avCH := map[string]string{
		DeployActionPass:  "通过",
		DeployActionAlarm: "告警",
		DeployActionBlock: "阻断",
	}

	avEn := map[string]string{
		DeployActionPass:  DeployActionPass,
		DeployActionAlarm: DeployActionAlarm,
		DeployActionBlock: DeployActionBlock,
	}
	if lang == model.LangEn {
		return avEn
	}

	return avCH
}
