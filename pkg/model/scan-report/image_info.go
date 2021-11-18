package scan_report

import (
	"encoding/json"

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
	_ = json.Unmarshal(t.WebshellInfoJSON, &t.WebshellInfo)
	_ = json.Unmarshal(t.MaliciousInfoJSON, &t.MaliciousInfo)
	_ = json.Unmarshal(t.VulnInfoJSON, &t.VulnInfo)
	_ = json.Unmarshal(t.MaliciousInfoJSON, &t.MaliciousInfo)
	_ = json.Unmarshal(t.LicenseInfoJSON, &t.LicenseInfo)
	_ = json.Unmarshal(t.SoftwareJSON, &t.Software)
	_ = json.Unmarshal([]byte(t.ScanEnableCollectionJson), &t.ScanEnableCollection)
	_ = json.Unmarshal(t.SensitiveFileJSON, &t.SensitiveFile)

	return nil
}
