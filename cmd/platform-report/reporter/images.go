package reporter

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"path"
	"time"

	json "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/types"
)

type ImageList struct {
	ID             int64  `gorm:"column:id"`
	ImageUUID      int64  `gorm:"column:image_uuid"`
	FullRepoName   string `gorm:"column:full_repo_name"`
	Tags           string `gorm:"column:tags"`
	Library        string `gorm:"column:library"`
	PrivilegedBoot int64  `gorm:"column:privileged_boot"`
	IsReinforce    int    `gorm:"column:is_reinforce"`
	FromType       int    `gorm:"column:from_type"`
}

type SingleScanDetail struct {
	Target string          `json:"target"`
	Class  string          `json:"class"`
	Type   string          `json:"type"`
	Vulns  []NewVulnDetail `json:"vulns"`
}

type NewVulnDetail struct {
	Trivy []types.DetectedVulnerability `json:"trivy"`
}

type ScanEnableCollection struct {
	EnvEnable       int `json:"env_enable"`
	SoftwareEnable  int `json:"software_enable"`
	SensitiveEnable int `json:"sensitive_enable"`
	LicenseEnable   int `json:"license_enable"`
}

type ScanImage struct {
	RiskScore                float64              `gorm:"column:risk_score"`
	SensitiveScore           float64              `gorm:"column:sensitive_score"`
	WebShellScore            float64              `gorm:"column:webshell_score"`
	VulnInfo                 []SingleScanDetail   `gorm:"-" json:"vuln_info"`
	VulnInfoJSON             datatypes.JSON       `gorm:"type:jsonb" json:"-"`     // 漏洞结果汇总
	MaliciousInfoJSON        datatypes.JSON       `gorm:"type:jsonb" json:"-"`     // 恶意文件
	MaliciousInfo            []model.Malicious    `gorm:"-" json:"malicious_info"` // 恶意文件
	ScanEnableCollection     ScanEnableCollection `gorm:"-" json:"scan_enable_collection"`
	ScanEnableCollectionJSON string               `gorm:"column:scan_enable_collection_json"`
	HasFixedVuln             int                  `gorm:"column:has_fixed_vuln" json:"has_fixed_vuln"`
}

type Record struct {
	ImageList
	ScanImage
	IsTrusted int `gorm:"column:is_trusted"`
}

func (r *Record) AfterFind(_ *gorm.DB) error {
	if len(r.MaliciousInfoJSON) > 0 {
		if err := json.Unmarshal(r.MaliciousInfoJSON, &r.MaliciousInfo); err != nil {
			logrus.Errorf("unmarshal MaliciousInfoJSON fail, err:%s, content:%s", err, r.MaliciousInfoJSON)
		}
	}

	if len(r.VulnInfoJSON) > 0 {
		if err := json.Unmarshal(r.VulnInfoJSON, &r.VulnInfo); err != nil {
			logrus.Errorf("unmarshal VulnInfoJSON fail, err:%s, content:%s", err, r.VulnInfoJSON)
		}
	}

	if len(r.ScanEnableCollectionJSON) > 0 {
		if err := json.Unmarshal(util.String2BytesNoCopy(r.ScanEnableCollectionJSON), &r.ScanEnableCollection); err != nil {
			logrus.Errorf("unmarshal ScanEnableCollectionJson fail, err:%s, content:%s", err, r.ScanEnableCollectionJSON)
		}
	}

	return nil
}

const (
	imageBatchSize = 500
	imageInterval  = time.Second
	riskScorePivot = 80
)

func LoadImagesReport(ctx context.Context, db *gorm.DB, endTimestamp int64) *model.ImagesReport {
	var (
		result = &model.ImagesReport{
			ImageCount:         &model.ImageCount{},
			VulnerabilityCount: &model.VulnerabilityCount{},
		}
		offsetTime          = util.GetTimeByMillisecondTimestamp(endTimestamp)
		offsetID            = int64(math.MaxInt64)
		vulnerabilityHash   = make(map[string]struct{})
		onlineImageUUIDList = getOnlineImageUUIDList(ctx, db)
	)

	onlineImageHash := make(map[int64]struct{}, len(onlineImageUUIDList))
	for _, uuid := range onlineImageUUIDList {
		onlineImageHash[uuid] = struct{}{}
	}

	for {
		images := loadImages(ctx, db, offsetID, offsetTime)
		if len(images) == 0 {
			break
		}

		offsetID = images[len(images)-1].ID
		for _, record := range images {
			doImageCountStatistics(result.ImageCount, record, onlineImageHash)
			doVulnerabilityStatistics(result.VulnerabilityCount, record, vulnerabilityHash)
			record.RiskScore = 100 - record.RiskScore
			if record.RiskScore < 0 {
				record.RiskScore = 0
			}
			if record.RiskScore <= riskScorePivot {
				result.RiskImages = append(result.RiskImages, &model.RiskImageItem{
					Name:      getImageName(record.Library, record.FullRepoName),
					Version:   record.Tags,
					RiskScore: record.RiskScore,
				})
			}
		}

		if len(images) < imageBatchSize {
			break
		}
		time.Sleep(imageInterval)
	}

	return result
}

func loadImages(ctx context.Context, db *gorm.DB, offsetID int64, offsetTime time.Time) []*Record {
	var records []*Record
	var selectFiled = []string{
		"t.library", "t.full_repo_name", "t.tags", "t.image_uuid", "t.id", "t.from_type",
		"t.privileged_boot", "t.is_reinforce",
		"s.risk_score", "s.webshell_score", "s.sensitive_score", "s.has_fixed_vuln",
		"s.vuln_info_json", "s.malicious_info_json", "s.scan_enable_collection_json",
		"ti.is_trusted",
	}
	load := func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, time.Second*10)
		defer oneCancel()
		return db.
			Table("ivan_scanner_image_list t").
			WithContext(oneCtx).
			Select(selectFiled).
			Where(" t.id < ? and t.created_at < ? ", offsetID, offsetTime).
			Joins("LEFT JOIN ivan_scanner_scan_images s ON t.id = s.image_id").
			Joins("LEFT JOIN ivan_scanner_trusted_images ti ON t.digest = ti.digest").
			Order("id desc").Limit(imageBatchSize).Find(&records).Error
	}

	if err := util.RetryWithBackoff(ctx, load); err != nil {
		logrus.Errorf("LoadImagesReport fail, err:%s", err)
	}

	return records
}

func doVulnerabilityStatistics(vulnerabilityCount *model.VulnerabilityCount, record *Record, vulnerabilityHash map[string]struct{}) {
	for i := range record.VulnInfo {
		for j := range record.VulnInfo[i].Vulns {
			for k := range record.VulnInfo[i].Vulns[j].Trivy {
				key := fmt.Sprintf("%s%s%s",
					record.VulnInfo[i].Vulns[j].Trivy[k].VulnerabilityID,
					record.VulnInfo[i].Vulns[j].Trivy[k].PkgName,
					record.VulnInfo[i].Vulns[j].Trivy[k].InstalledVersion,
				)
				if _, ok := vulnerabilityHash[key]; ok {
					continue
				}
				vulnerabilityHash[key] = struct{}{}

				vulnerabilityCount.TotalVulnerabilityCount++
				severity := record.VulnInfo[i].Vulns[j].Trivy[k].Severity
				switch severity {
				case model.SeverityCritical:
					vulnerabilityCount.CriticalVulnerabilityCount++
				case model.SeverityHigh:
					vulnerabilityCount.HighVulnerabilityCount++
				case model.SeverityMedium:
					vulnerabilityCount.MediumVulnerabilityCount++
				case model.SeverityLow:
					vulnerabilityCount.LowVulnerabilityCount++
				default:
					vulnerabilityCount.UnknownVulnerabilityCount++
				}
			}
		}
	}
}

func doImageCountStatistics(imageCount *model.ImageCount, record *Record, onlineImageHash map[int64]struct{}) {
	// 总数量
	imageCount.TotalImageCount++

	// 在线镜像数量
	if record.FromType != model.ImageFromTypeCICD {
		if _, ok := onlineImageHash[record.ImageUUID]; ok {
			imageCount.OnlineImageCount++
		}
	}

	// 可信镜像
	if record.IsTrusted == 1 {
		imageCount.TrustedImageCount++
	}
	// 存在漏洞镜像
	if len(record.VulnInfo) != 0 {
		imageCount.VulnerabilityCount++
	}
	// 存在敏感文件
	if record.SensitiveScore > 0 {
		imageCount.SensitiveFileCount++
	}
	// 存在恶意文件
	if len(record.MaliciousInfo) != 0 {
		imageCount.MaliciousCount++
	}
	// 存在webshell
	if record.WebShellScore > 0 {
		imageCount.WebShellCount++
	}
	// 存在异常环境变量
	if record.ScanEnableCollection.EnvEnable == 1 {
		imageCount.AbnormalEnvCount++
	}
	// 存在不允许开源许可
	if record.ScanEnableCollection.LicenseEnable == 1 {
		imageCount.LicenceCount++
	}
	// 存在不合规软件
	if record.ScanEnableCollection.SoftwareEnable == 1 {
		imageCount.SoftwareCount++
	}
	// 存在特权启动
	if record.PrivilegedBoot == 1 {
		imageCount.PrivilegedCount++
	}
	// 可修复镜像
	if record.HasFixedVuln == 1 {
		imageCount.RepairableImageCount++
	}
	// 已加固镜像
	if record.IsReinforce == 1 {
		imageCount.ReinforcedImageCount++
	}
}

func getOnlineImageUUIDList(ctx context.Context, db *gorm.DB) []int64 {
	var imageUUIDList []int64
	get := func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, time.Second*5)
		defer oneCancel()

		return db.WithContext(oneCtx).Model(&model.TensorContainer{}).
			Select("distinct(image_uuid)").Scan(&imageUUIDList).Error
	}

	if err := util.RetryWithBackoff(ctx, get); err != nil {
		logrus.Errorf("getOnlineImageUUIDList fail, err:%s", err)
	}

	return imageUUIDList
}

func getImageName(library, fullName string) string {
	u, err := url.Parse(library)
	if err != nil {
		return path.Join(library, fullName)
	}

	u.Path = path.Join(u.Path, fullName)
	return u.String()
}
