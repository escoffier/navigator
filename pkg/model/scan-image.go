package model

import (
	"encoding/json"
	"time"

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

	VulnInfo                 []SingleScanDetail         `gorm:"-" json:"vuln_info"`
	VulnInfoJSON             []byte                     `gorm:"type:MediumBlob" json:"-"` // 漏洞结果汇总
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

	CheckSum uint64 `gorm:"column:check_sum" json:"check_sum"` // 这一行数据的check值，且于判断这一行数据是否有变动，如果没有变动，就不再更新
}

func (si ScanImage) TableName() string {
	return "ivan_scanner_scan_images"
}

func ExistFlag(value uint64, flag int64) bool {
	return (value>>flag)&1 == 1
}

func (si *ScanImage) GenImageFlag(preFlag uint64) uint64 {

	var flag uint64

	if si.VulnScore > 0 {
		flag = 1<<FlagHasVuln + flag
	}
	if si.SensitiveScore > 0 {
		flag = 1<<FlagHasSensitive + flag
	}
	if si.VirusScore > 0 {
		flag = 1<<FlagHasMalicious + flag
	}
	if si.WebshellScore > 0 {
		flag = 1<<FlagHasWebshell + flag
	}
	for i := range si.EnvKeyValue {
		if si.EnvKeyValue[i].IsAbnormal > 0 {
			flag = 1<<FlagHasExceptEnv + flag
			break
		}
	}

	if si.ScanEnableCollection.SoftwareEnable > 0 {
		flag = 1<<FlagHasSoftware + flag
	}

	if si.ScanEnableCollection.LicenseEnable > 0 {
		flag = 1<<FlagHasExceptLicense + flag
	}
	if si.HasFixedVuln > 0 {
		flag = 1<<FlagHasFixedVuln + flag
	}

	// 以下部分是image所特有的flag
	if ExistFlag(preFlag, FlagBaseImage) {
		flag = 1<<FlagBaseImage + flag
	}
	if ExistFlag(preFlag, FlagPrivilegedBoot) {
		flag = 1<<FlagPrivilegedBoot + flag
	}
	if ExistFlag(preFlag, FlagReinforced) {
		flag = 1<<FlagReinforced + flag
	}

	return flag
}

func (si *ScanImage) Deserialize() {
	vulnInfo := make([]SingleScanDetail, 0)
	if len(si.VulnInfoJSON) > 0 {
		if err := json.Unmarshal(si.VulnInfoJSON, &vulnInfo); err != nil {
			logging.GetLogger().Error().Err(err).Int64("imageID", si.ImageID).Int64("ID", si.ID).Msg("Unmarshal VulnInfo")
		}
	}
	si.VulnInfo = vulnInfo

	perLayerReport := make([]VulnerabilityLayerReport, 0)
	if len(si.PerLayerReportJSON) > 0 {
		if err := json.Unmarshal(si.PerLayerReportJSON, &perLayerReport); err != nil {
			logging.GetLogger().Error().Err(err).Int64("imageID", si.ImageID).Int64("ID", si.ID).Msg("Unmarshal PerLayerReport")
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
		}
	}
	si.SensitiveFile = sensitiveFile

	softs := make([]Software, 0)
	if len(si.SoftwareJSON) > 0 {
		if err := json.Unmarshal(si.SoftwareJSON, &softs); err != nil {
			logging.GetLogger().Error().Err(err).Int64("imageID", si.ImageID).Int64("ID", si.ID).Msg("Unmarshal SoftWare")
		}
	}
	si.Software = softs

	maliciousInfo := make([]Malicious, 0)
	if len(si.MaliciousInfoJSON) > 0 {
		if err := json.Unmarshal(si.MaliciousInfoJSON, &maliciousInfo); err != nil {
			logging.GetLogger().Error().Err(err).Int64("imageID", si.ImageID).Int64("ID", si.ID).Msg("Unmarshal Malicious")
		}
	}
	si.MaliciousInfo = maliciousInfo

	webShellInfo := make([]Webshell, 0)
	if len(si.WebshellInfoJSON) > 0 {
		if err := json.Unmarshal(si.WebshellInfoJSON, &webShellInfo); err != nil {
			logging.GetLogger().Error().Err(err).Int64("imageID", si.ImageID).Int64("ID", si.ID).Msg("Unmarshal Webshell")
		}
	}
	si.WebshellInfo = webShellInfo

	envInfo := make([]EnvKeyValue, 0)
	if len(si.EnvJSON) > 0 {
		if err := json.Unmarshal(si.EnvJSON, &envInfo); err != nil {
			logging.GetLogger().Error().Err(err).Int64("imageID", si.ImageID).Int64("ID", si.ID).Msg("Unmarshal Env")
		}
	}

	si.EnvKeyValue = envInfo

	license := make([]LicenseInfo, 0)
	if len(si.LicenseInfoJSON) > 0 {
		if err := json.Unmarshal(si.LicenseInfoJSON, &license); err != nil {
			logging.GetLogger().Error().Err(err).Int64("imageID", si.ImageID).Int64("ID", si.ID).Msgf("Unmarshal LicenseInfo")
		}
	}
	si.LicenseInfo = license

	scanEnableCollection := ScanEnableCollection{}
	if len(si.ScanEnableCollectionJson) > 0 {
		if err := json.Unmarshal([]byte(si.ScanEnableCollectionJson), &scanEnableCollection); err != nil {
			logging.GetLogger().Err(err).Msg("SearchScanImage Unmarshal")
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
