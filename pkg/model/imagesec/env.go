package imagesec

import (
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 镜像环境变量
type ImageEnv struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	UniqueID      uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	ImageUniqueID uint64 `gorm:"column:image_unique_id" json:"imageUniqueID,string"`
	Key           string `gorm:"column:key" json:"key"`
	Value         string `gorm:"column:value" json:"value"`
	LayerDigest   string `gorm:"column:layer_digest" json:"layerDigest"`

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds

	PolicyDetect PolicyDetect `gorm:"-" json:"policyDetect"` // 对各个策略的检测结果
}

func (vi *ImageEnv) AddPolicyDetect(detect []*ImageDetectResult) {
	for i := range detect {
		if detect[i].UniqueTarget == vi.UniqueID {
			vi.PolicyDetect = detect[i].ToPolicyDetect()
		}
	}
}

func (vi *ImageEnv) GenUniqueID() uint64 {
	key := fmt.Sprintf(UniqueEnvFormat, vi.ImageUniqueID, vi.Key, vi.Value, vi.LayerDigest)
	uid := util.GenerateUUID64(key)
	return uid
}

func (vi *ImageEnv) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.Key == "" {
		return fmt.Errorf("not get Key")
	}
	if vi.UniqueID == 0 {
		vi.UniqueID = vi.GenUniqueID()
	}
	if vi.UniqueID <= 0 {
		return fmt.Errorf("not get uniqueID")
	}
	return nil
}

func (vi *ImageEnv) TableName() string {
	if vi == nil {
		return ""
	}
	return "ivan_scan_image_env"
}

func (vi *ImageEnv) Same(after *ImageEnv) bool {
	if vi.UniqueID <= 0 || after.UniqueID <= 0 {
		vi.UniqueID = vi.GenUniqueID()
		after.UniqueID = after.GenUniqueID()
	}
	return vi.UniqueID == after.UniqueID
}
