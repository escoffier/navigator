package model

import (
	"fmt"
	"strings"
	"time"

	json "github.com/json-iterator/go"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanImage struct { // 镜像结果// 加上镜像结果,对应原来的scantasks表
	ID             int64 `gorm:"primaryKey"`
	CreatedAt      *time.Time
	UpdatedAt      *time.Time
	DeletedAt      int
	ImageID        int64   `gorm:"column:image_id;uniqueIndex:idx_scan_image"`
	RiskScore      float64 `gorm:"column:risk_score" json:"risk_score"`
	VulnScore      float64 `gorm:"column:vuln_score" json:"vuln_score"`
	SensitiveScore float64 `gorm:"column:sensitive_score" json:"sensitive_score"`
	VirusScore     float64 `gorm:"column:virus_score" json:"virus_score"`
	WebshellScore  float64 `gorm:"column:webshell_score" json:"webshell_score"`

	VulnInfo                 []*Vuln                    `gorm:"-" json:"vuln_info"`       //
	VulnInfoJSON             []byte                     `gorm:"type:MediumBlob" json:"-"` // 漏洞结果汇总，优化之后，这个字段不存保存数据
	PkgInfoJSON              []byte                     `gorm:"type:MediumBlob" json:"-"` // 软件包信息
	MaliciousInfoJSON        []byte                     `gorm:"type:MediumBlob" json:"-"` // 恶意文件
	MaliciousInfo            []Malicious                `gorm:"-" json:"malicious_info"`  // 恶意文件
	WebshellInfo             []Webshell                 `gorm:"-" json:"webshell_info"`   // webshell
	WebshellInfoJSON         []byte                     `gorm:"type:MediumBlob" json:"-"` // webshell
	SensitiveFile            []Sensitive                `gorm:"-" json:"sensitive_file"`
	SensitiveFileJSON        []byte                     `gorm:"type:MediumBlob" json:"-"` // 敏感文件
	PerLayerReport           []VulnerabilityLayerReport `gorm:"-" json:"per_layer_report"`
	PerLayerReportJSON       []byte                     `gorm:"type:MediumBlob" json:"-"` // 层结果汇总
	LicenseInfo              []LicenseInfo              `gorm:"-" json:"license_info"`
	LicenseInfoJSON          []byte                     `gorm:"type:MediumBlob" json:"-"`
	Software                 []Software                 `gorm:"-" json:"software"`
	SoftwareJSON             []byte                     `gorm:"type:MediumBlob" json:"-"`
	EnvKeyValue              []EnvKeyValue              `gorm:"-" json:"env_key_value"`
	EnvJSON                  []byte                     `gorm:"type:MediumBlob" json:"-"`
	OverallSeverity          string                     `gorm:"type:varchar(255)" json:"overallSeverity"` // 评级
	OverallSeverityInt       int                        `json:"overallSeverityInt"`                       // 评级int
	SeverityHistogram        SeverityHistogramInfo      `gorm:"-" json:"severityHistogram"`               // 评级集合
	SeverityHistogramJSON    []byte                     `gorm:"type:MediumBlob"`
	ScanEnableCollection     ScanEnableCollection       `gorm:"-" json:"scan_enable_collection"`
	ScanEnableCollectionJson string                     `gorm:"type:varchar(255);column:scan_enable_collection_json"`
	HasFixedVuln             int                        `gorm:"column:has_fixed_vuln" json:"has_fixed_vuln"`

	ScanTaskID string `gorm:"type:varchar(255)" json:"scan_task_id"`
	Status     string `gorm:"type:varchar(255)" json:"status"`  // 扫描状态
	Message    string `gorm:"type:varchar(255)" json:"message"` // 错误信息
	StartedAt  int64  // 扫描开始时间
	FinishAt   int64  // 扫描结束时间

	CheckSum uint64 `gorm:"column:check_sum" json:"check_sum,string"` // 这一行数据的check值，且于判断这一行数据是否有变动，如果没有变动，就不再更新
}

func (si *ScanImage) TableName() string {
	return "ivan_scanner_scan_images"
}

func ExistFlag(value uint64, flag uint64) bool {
	return (value>>flag)&1 == 1
}

func (si *ScanImage) GenImageFlag(preFlag uint64) uint64 {
	si.Deserialize()
	si.Serialize()

	if si.VulnScore > 0 {
		preFlag = util.SetBit1(preFlag, FlagHasVuln)
	} else {
		preFlag = util.SetBit0(preFlag, FlagHasVuln)
	}

	if len(si.SensitiveFile) > 0 {
		preFlag = util.SetBit1(preFlag, FlagHasSensitive)
	} else {
		preFlag = util.SetBit0(preFlag, FlagHasSensitive)
	}

	if len(si.MaliciousInfo) > 0 {
		preFlag = util.SetBit1(preFlag, FlagHasMalicious)
	} else {
		preFlag = util.SetBit0(preFlag, FlagHasMalicious)
	}

	if si.WebshellScore > 0 {
		preFlag = util.SetBit1(preFlag, FlagHasWebshell)
	} else {
		preFlag = util.SetBit0(preFlag, FlagHasWebshell)
	}
	env := false
	for i := range si.EnvKeyValue {
		if si.EnvKeyValue[i].IsAbnormal > 0 {
			preFlag = util.SetBit1(preFlag, FlagHasExceptEnv)
			env = true
			break
		}
	}
	if !env {
		preFlag = util.SetBit0(preFlag, FlagHasExceptEnv)
	}

	if len(si.Software) > 0 {
		preFlag = util.SetBit1(preFlag, FlagHasSoftware)
	} else {
		preFlag = util.SetBit0(preFlag, FlagHasSoftware)
	}

	if len(si.LicenseInfo) > 0 {
		preFlag = util.SetBit1(preFlag, FlagHasExceptLicense)
	} else {
		preFlag = util.SetBit0(preFlag, FlagHasExceptLicense)
	}
	if si.HasFixedVuln > 0 {
		preFlag = util.SetBit1(preFlag, FlagHasFixedVuln)
	} else {
		preFlag = util.SetBit0(preFlag, FlagHasFixedVuln)
	}

	return preFlag
}

func (si *ScanImage) Deserialize() {
	perLayerReport := make([]VulnerabilityLayerReport, 0)
	if len(si.PerLayerReportJSON) > 0 {
		if err := json.Unmarshal(si.PerLayerReportJSON, &perLayerReport); err != nil {
			logging.GetLogger().Error().Err(err).Int64("imageID", si.ImageID).Int64("ID", si.ID).Msg("Unmarshal PerLayerReport")
			perLayerReport = make([]VulnerabilityLayerReport, 0)
		}
	}
	si.PerLayerReport = perLayerReport

	severityHistogram := new(SeverityHistogramInfo)
	if len(si.SeverityHistogramJSON) > 0 {
		if err := json.Unmarshal(si.SeverityHistogramJSON, severityHistogram); err != nil {
			logging.GetLogger().Error().Err(err).Int64("imageID", si.ImageID).Int64("ID", si.ID).Msg("Unmarshal PerLayerReport")
		} else {
			si.SeverityHistogram = *severityHistogram
		}
	}

	sensitiveFile := make([]Sensitive, 0)
	if len(si.SensitiveFileJSON) > 0 {
		if err := json.Unmarshal(si.SensitiveFileJSON, &sensitiveFile); err != nil {
			logging.GetLogger().Error().Err(err).Int64("imageID", si.ImageID).Int64("ID", si.ID).Msg("Unmarshal SensitiveFile")
			sensitiveFile = make([]Sensitive, 0)
		}
	}
	si.SensitiveFile = sensitiveFile

	softs := make([]Software, 0)
	if len(si.SoftwareJSON) > 0 {
		if err := json.Unmarshal(si.SoftwareJSON, &softs); err != nil {
			logging.GetLogger().Error().Err(err).Int64("imageID", si.ImageID).Int64("ID", si.ID).Msg("Unmarshal SoftWare")
			softs = make([]Software, 0)
		}
	}
	si.Software = softs

	maliciousInfo := make([]Malicious, 0)
	if len(si.MaliciousInfoJSON) > 0 {
		if err := json.Unmarshal(si.MaliciousInfoJSON, &maliciousInfo); err != nil {
			logging.GetLogger().Error().Err(err).Int64("imageID", si.ImageID).Int64("ID", si.ID).Msg("Unmarshal Malicious")
			maliciousInfo = make([]Malicious, 0)
		}
	}
	si.MaliciousInfo = maliciousInfo

	webShellInfo := make([]Webshell, 0)
	if len(si.WebshellInfoJSON) > 0 {
		if err := json.Unmarshal(si.WebshellInfoJSON, &webShellInfo); err != nil {
			logging.GetLogger().Error().Err(err).Int64("imageID", si.ImageID).Int64("ID", si.ID).Msg("Unmarshal Webshell")
			webShellInfo = make([]Webshell, 0)
		}
	}
	si.WebshellInfo = webShellInfo

	envInfo := make([]EnvKeyValue, 0)
	if len(si.EnvJSON) > 0 {
		if err := json.Unmarshal(si.EnvJSON, &envInfo); err != nil {
			logging.GetLogger().Error().Err(err).Int64("imageID", si.ImageID).Int64("ID", si.ID).Msg("Unmarshal Env")
			envInfo = make([]EnvKeyValue, 0)
		}
	}

	si.EnvKeyValue = envInfo

	license := make([]LicenseInfo, 0)
	if len(si.LicenseInfoJSON) > 0 {
		if err := json.Unmarshal(si.LicenseInfoJSON, &license); err != nil {
			logging.GetLogger().Error().Err(err).Int64("imageID", si.ImageID).Int64("ID", si.ID).Msgf("Unmarshal LicenseInfo")
			license = make([]LicenseInfo, 0)
		}
	}
	si.LicenseInfo = license

	scanEnableCollection := ScanEnableCollection{}
	if len(si.ScanEnableCollectionJson) > 0 {
		if err := json.Unmarshal([]byte(si.ScanEnableCollectionJson), &scanEnableCollection); err != nil {
			logging.GetLogger().Err(err).Msg("SearchScanImage Unmarshal")
			scanEnableCollection = ScanEnableCollection{}
		}
	}
	si.ScanEnableCollection = scanEnableCollection
}

func (si *ScanImage) Serialize() {
	if len(si.VulnInfo) > 0 {
		if bytes, err := json.Marshal(si.VulnInfo); err == nil {
			si.VulnInfoJSON = bytes
		}
	}

	if len(si.PerLayerReport) > 0 {
		if bytes, err := json.Marshal(si.PerLayerReport); err == nil {
			si.PerLayerReportJSON = bytes
		}
	}

	if bytes, err := json.Marshal(si.SeverityHistogram); err == nil {
		si.SeverityHistogramJSON = bytes
	}

	if len(si.SensitiveFile) > 0 {
		if bytes, err := json.Marshal(si.SensitiveFile); err == nil {
			si.SensitiveFileJSON = bytes
		}
	}

	if len(si.Software) > 0 {
		if bytes, err := json.Marshal(si.Software); err == nil {
			si.SoftwareJSON = bytes
		}
	}

	if len(si.MaliciousInfo) > 0 {
		if bytes, err := json.Marshal(si.MaliciousInfo); err == nil {
			si.MaliciousInfoJSON = bytes
		}
	}

	if len(si.WebshellInfo) > 0 {
		if bytes, err := json.Marshal(si.WebshellInfo); err == nil {
			si.WebshellInfoJSON = bytes
		}
	}

	if len(si.EnvKeyValue) > 0 {
		if bytes, err := json.Marshal(si.EnvKeyValue); err == nil {
			si.EnvJSON = bytes
		}
	}

	if len(si.LicenseInfo) > 0 {
		if bytes, err := json.Marshal(si.LicenseInfo); err == nil {
			si.LicenseInfoJSON = bytes
		}
	}

	if bytes, err := json.Marshal(si.ScanEnableCollection); err == nil {
		si.ScanEnableCollectionJson = string(bytes)
	}
}

func (si *ScanImage) GetCheckSum() uint64 {
	si.Serialize()
	si.Deserialize()
	createdAt, updatedAt, preCheck, finishAt, startAt, message, status := si.CreatedAt,
		si.UpdatedAt, si.CheckSum, si.FinishAt, si.StartedAt, si.Message, si.Status
	si.CreatedAt = nil
	si.UpdatedAt = nil
	si.CheckSum = 0
	si.FinishAt = 0
	si.StartedAt = 0
	si.Status = ""
	si.Message = ""

	bys, err := json.Marshal(si)
	si.CreatedAt, si.UpdatedAt, si.CheckSum, si.FinishAt, si.StartedAt,
		si.Message, si.Status = createdAt, updatedAt, preCheck, finishAt, startAt, message, status
	if err != nil {
		return 0
	}
	return util.GenerateUUID64(string(bys))
}

type ImageFlagGroup struct {
	Flag  uint64 `gorm:"column:flag" json:"flag"`
	Count int64  `gorm:"column:cnt" json:"count"`
}

type ImageVirus struct {
	ID        int64  `gorm:"primaryKey" json:"id"`
	UniqueID  uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	Filename  string `gorm:"column:filename" json:"filename"`
	Filepath  string `gorm:"column:filepath" json:"filepath"`
	Name      string `gorm:"column:name" json:"name"`
	CreatedAt int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *ImageVirus) Same(after *ImageVirus) bool {
	if vi.Filename != after.Filename || vi.Filepath != after.Filepath || vi.Name != after.Name {
		return false
	}
	return true
}

func (vi *ImageVirus) TableName() string {
	return "ivan_scanner_virus"
}

func (vi *ImageVirus) GenUniqueID() uint64 {
	key := fmt.Sprintf(consts.UniqueVirusFamat, vi.Name, vi.Filename, vi.Filepath)
	uid := util.GenerateUUID64(key)
	return uid
}

type ImageWebShell struct {
	ID        int64    `gorm:"primaryKey" json:"id"`
	UniqueID  uint64   `gorm:"column:unique_id" json:"uniqueID,string"`
	Filename  string   `gorm:"column:filename" json:"filename"`
	Filepath  string   `gorm:"column:filepath" json:"filepath"`
	Score     int64    `gorm:"column:score" json:"score"`                               // the score of webshell detection
	Codes     []string `gorm:"column:codes" json:"codes"`                               // the code-segments which contain webshell
	CreatedAt int64    `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64    `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (ws *ImageWebShell) TableName() string {
	return "ivan_scanner_webshell"
}

func (ws *ImageWebShell) GenUniqueVuln() uint64 {
	key := fmt.Sprintf(consts.UniqueWebshellFamat, ws.Filename, ws.Filepath, strings.Join(ws.Codes, "|"))
	uid := util.GenerateUUID64(key)
	return uid
}

type ImageSensitiveFile struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	UniqueID      uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	Name          string `gorm:"column:name" json:"name"`
	Description   string `gorm:"column:description" json:"description"`
	DescriptionEn string `gorm:"column:description_en" json:"descriptionEn"`
	DescriptionZh string `gorm:"column:description_zh" json:"descriptionZh"`
	CreatedAt     int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (ws *ImageSensitiveFile) TableName() string {
	return "ivan_scanner_sensitive"
}

func (ws *ImageSensitiveFile) GenUniqueID() uint64 {
	key := fmt.Sprintf(consts.UniqueSensitiveFamat, ws.Name, ws.Description)
	uid := util.GenerateUUID64(key)
	return uid
}

func (ws *ImageSensitiveFile) Same(after *ImageSensitiveFile) bool {
	if ws.Name != after.Name || ws.Description != after.Description || ws.DescriptionEn != after.DescriptionEn ||
		ws.DescriptionZh != after.DescriptionZh {
		return false
	}
	return true
}

type ScanSensitiveToImage struct {
	ID           int64  `gorm:"primaryKey" json:"id"`
	UniqueID     uint64 `gorm:"column:unique_id" json:"uniqueID,string"` // 数据库的中唯一建，去重效率高
	UniqueTarget uint64 `gorm:"column:unique_target" json:"uniqueTarget,string"`
	ImageID      int64  `gorm:"column:image_id" json:"imageID"`
	Flag         uint64 `gorm:"column:flag" json:"flag"` // 其他的信息:比如license是否允许，软件包是否允许等等，用于筛选
	LayerDigest  string `gorm:"column:layer_digest" json:"layerDigest"`
	CreatedAt    int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt    int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *ScanSensitiveToImage) GenUniqueVuln() uint64 {
	key := fmt.Sprintf("%d-%d-%s", vi.ImageID, vi.UniqueTarget, vi.LayerDigest)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

func (vi *ScanSensitiveToImage) Same(after *ScanSensitiveToImage) bool {
	if vi.LayerDigest != after.LayerDigest || vi.Flag != after.Flag || vi.ImageID != after.ImageID ||
		vi.UniqueTarget != after.UniqueTarget {
		return false
	}
	return true
}

func (vi *ScanSensitiveToImage) TableName() string {
	return "ivan_sensitive_issue_image"
}

type ScanSoftwareToImage struct {
	ID           int64  `gorm:"primaryKey" json:"id"`
	UniqueID     uint64 `gorm:"column:unique_id" json:"uniqueID,string"` // 数据库的中唯一建，去重效率高
	UniqueTarget uint64 `gorm:"column:unique_target" json:"uniqueTarget,string"`
	ImageID      int64  `gorm:"column:image_id" json:"imageID"`
	Flag         uint64 `gorm:"column:flag" json:"flag"` // 其他的信息:比如license是否允许，软件包是否允许等等，用于筛选
	LayerDigest  string `gorm:"column:layer_digest" json:"layerDigest"`
	CreatedAt    int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt    int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *ScanSoftwareToImage) GenUniqueVuln() uint64 {
	key := fmt.Sprintf("%d-%d-%s", vi.ImageID, vi.UniqueTarget, vi.LayerDigest)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

func (vi *ScanSoftwareToImage) Same(after *ScanSoftwareToImage) bool {
	if vi.LayerDigest != after.LayerDigest || vi.Flag != after.Flag || vi.ImageID != after.ImageID ||
		vi.UniqueTarget != after.UniqueTarget {
		return false
	}
	return true
}

func (vi *ScanSoftwareToImage) TableName() string {
	return "ivan_software_issue_image"
}

type ScanVirusToImage struct {
	ID           int64  `gorm:"primaryKey" json:"id"`
	UniqueID     uint64 `gorm:"column:unique_id" json:"uniqueID,string"` // 数据库的中唯一建，去重效率高
	UniqueTarget uint64 `gorm:"column:unique_target" json:"uniqueTarget,string"`
	ImageID      int64  `gorm:"column:image_id" json:"imageID"`
	Flag         uint64 `gorm:"column:flag" json:"flag"` // 其他的信息:比如license是否允许，软件包是否允许等等，用于筛选
	LayerDigest  string `gorm:"column:layer_digest" json:"layerDigest"`
	CreatedAt    int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt    int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *ScanVirusToImage) GenUniqueID() uint64 {
	key := fmt.Sprintf("%d-%d-%s", vi.ImageID, vi.UniqueTarget, vi.LayerDigest)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

func (vi *ScanVirusToImage) Same(after *ScanVirusToImage) bool {
	if vi.LayerDigest != after.LayerDigest || vi.Flag != after.Flag || vi.ImageID != after.ImageID ||
		vi.UniqueTarget != after.UniqueTarget {
		return false
	}
	return true
}

func (vi *ScanVirusToImage) TableName() string {
	return "ivan_virus_issue_image"
}

type ScanIssueToImageWebshell struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	UniqueID      uint64 `gorm:"column:unique_id" json:"uniqueID,string"` // 数据库的中唯一建，去重效率高
	SecurityIssue int64  `gorm:"security_issue" json:"securityIssue"`
	UniqueTarget  uint64 `gorm:"column:unique_target" json:"uniqueTarget,string"`
	ImageID       int64  `gorm:"column:image_id" json:"imageID"`
	Flag          uint64 `gorm:"column:flag" json:"flag"` // 其他的信息:比如license是否允许，软件包是否允许等等，用于筛选
	LayerDigest   string `gorm:"column:layer_digest" json:"layerDigest"`
	CreatedAt     int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *ScanIssueToImageWebshell) GenUniqueVuln() uint64 {
	key := fmt.Sprintf("%d-%d-%d-%s", vi.ImageID, vi.SecurityIssue, vi.UniqueTarget, vi.LayerDigest)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

func (vi *ScanIssueToImageWebshell) Same(after *ScanIssueToImageWebshell) bool {
	if vi.LayerDigest != after.LayerDigest || vi.Flag != after.Flag || vi.ImageID != after.ImageID ||
		vi.UniqueTarget != after.UniqueTarget || vi.SecurityIssue != after.SecurityIssue {
		return false
	}
	return true
}

func (vi *ScanIssueToImageWebshell) TableName() string {
	return "ivan_scanner_issue_image_webshell"
}

type ImageSoftware struct {
	ID        int64  `gorm:"primaryKey" json:"id"`
	UniqueID  uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	Name      string `gorm:"column:name" json:"name"`
	Version   string `gorm:"column:version" json:"version"`
	License   string `gorm:"column:license" json:"license"`
	CreatedAt int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds

	Flag uint64 `gorm:"-" json:"flag"`
}

func (s *ImageSoftware) GenUniqueID() uint64 {
	key := fmt.Sprintf(consts.UniqueSoftwareFamat, s.Name, s.Version)
	uid := util.GenerateUUID64(key)
	return uid
}

func (s *ImageSoftware) TableName() string {
	return "ivan_scanner_software"
}

func (s *ImageSoftware) Same(after *ImageSoftware) bool {
	if s.Name != after.Name || s.Version != after.Version || s.License != after.License {
		return false
	}
	return true
}

type ImageEnv struct {
	ID        int64  `gorm:"primaryKey" json:"id"`
	UniqueID  uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	ImageID   int64  `gorm:"column:image_id" json:"imageID"`
	Key       string `gorm:"column:key" json:"key"`
	Value     string `gorm:"column:value" json:"value"`
	Normal    bool   `gorm:"column:normal" json:"normal"`
	CreatedAt int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *ImageEnv) GenUniqueID() uint64 {
	key := fmt.Sprintf(consts.UniqueENVFamat, vi.Key, vi.Value, vi.Normal)
	uid := util.GenerateUUID64(key)
	return uid
}

func (vi *ImageEnv) TableName() string {
	return "ivan_scanner_env"
}

func (vi *ImageEnv) Same(after *ImageEnv) bool {
	if vi.Normal != after.Normal || vi.Key != after.Key || vi.Value != after.Value || vi.ImageID != after.ImageID {
		return false
	}
	return true
}
