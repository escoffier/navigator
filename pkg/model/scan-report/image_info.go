package scan_report

import (
	json "github.com/json-iterator/go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ImageInfo struct {
	model.ImageList       // 镜像信息
	model.ScanImage       // 扫描信息
	IsTrusted       uint8 `gorm:"column:is_trusted"` // 是否可信
	ContainerUUID   int64 `gorm:"column:imageuuid"`  // left join tensor_containers 的image_uuid
}

func (t *ImageInfo) AfterFind(_ *gorm.DB) error {
	if len(t.WebshellInfoJSON) > 0 {
		if err := json.Unmarshal(t.WebshellInfoJSON, &t.WebshellInfo); err != nil {
			logging.Get().Err(err).Int64("imageID", t.ImageID).Msg("ImageInfo.AfterFind")
		}
	}

	if len(t.MaliciousInfoJSON) > 0 {
		if err := json.Unmarshal(t.MaliciousInfoJSON, &t.MaliciousInfo); err != nil {
			logging.Get().Err(err).Int64("imageID", t.ImageID).Msg("ImageInfo.AfterFind")
		}
	}

	if len(t.LicenseInfoJSON) > 0 {
		if err := json.Unmarshal(t.LicenseInfoJSON, &t.LicenseInfo); err != nil {
			logging.Get().Err(err).Int64("imageID", t.ImageID).Msg("ImageInfo.AfterFind")
		}
	}

	if len(t.SoftwareJSON) > 0 {
		if err := json.Unmarshal(t.SoftwareJSON, &t.Software); err != nil {
			logging.Get().Err(err).Int64("imageID", t.ImageID).Msg("ImageInfo.AfterFind")
		}
	}

	if len(t.ScanEnableCollectionJson) > 0 {
		if err := json.Unmarshal([]byte(t.ScanEnableCollectionJson), &t.ScanEnableCollection); err != nil {
			logging.Get().Err(err).Int64("imageID", t.ImageID).Msg("ImageInfo.AfterFind")
		}
	}

	if len(t.SensitiveFileJSON) > 0 {
		if err := json.Unmarshal(t.SensitiveFileJSON, &t.SensitiveFile); err != nil {
			logging.Get().Err(err).Int64("imageID", t.ImageID).Msg("ImageInfo.AfterFind")
		}
	}

	return nil
}
