package imagesec

import (
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type SensitiveFile struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	UniqueID      uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	Name          string `gorm:"column:name" json:"name"`
	DescriptionEn string `gorm:"column:description_en" json:"descriptionEn"`
	DescriptionZh string `gorm:"column:description_zh" json:"descriptionZh"`

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds

	PolicyDetect PolicyDetect `gorm:"-" json:"policyDetect"` // 对各个策略的检测结果
}

func (vi *SensitiveFile) TableName() string {
	return "ivan_scan_image_sensitive"
}

func (vi *SensitiveFile) GenUniqueID() uint64 {
	key := fmt.Sprintf(UniqueSensitiveFormat, vi.Name, vi.DescriptionEn, vi.DescriptionZh)
	uid := util.GenerateUUID64(key)
	return uid
}

func (vi *SensitiveFile) Same(after *SensitiveFile) bool {
	if vi.Name != after.Name || vi.DescriptionEn != after.DescriptionEn ||
		vi.DescriptionZh != after.DescriptionZh {
		return false
	}
	return true
}

func (vi *SensitiveFile) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.Name == "" {
		return fmt.Errorf("not get Name")
	}
	if vi.UniqueID == 0 {
		vi.UniqueID = vi.GenUniqueID()
	}
	if vi.UniqueID <= 0 {
		return fmt.Errorf("not get uniqueID")
	}
	return nil
}

type SensitiveToImage struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	UniqueID      uint64 `gorm:"column:unique_id" json:"uniqueID,string"` // 数据库的中唯一建，去重效率高
	UniqueTarget  uint64 `gorm:"column:unique_target" json:"uniqueTarget,string"`
	ImageUniqueID uint64 `gorm:"column:image_unique_id" json:"imageUniqueID,string"`
	LayerDigest   string `gorm:"column:layer_digest" json:"layerDigest"`
	CreatedAt     int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *SensitiveToImage) GenUniqueID() uint64 {
	if vi.UniqueID > 0 {
		return vi.UniqueID
	}
	key := fmt.Sprintf("%d-%d-%s", vi.ImageUniqueID, vi.UniqueTarget, vi.LayerDigest)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

func (vi *SensitiveToImage) Same(after *SensitiveToImage) bool {
	if vi.LayerDigest != after.LayerDigest || vi.ImageUniqueID != after.ImageUniqueID ||
		vi.UniqueTarget != after.UniqueTarget {
		return false
	}
	return true
}

func (vi *SensitiveToImage) TableName() string {
	// 由于仓库镜像，节点镜像，CI镜像的数据结构一致，但是数据量较大，所以要做分表处理
	if vi == nil {
		return ""
	}
	return "ivan_image_sensitive_issue"
}
