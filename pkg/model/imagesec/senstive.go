package imagesec

import (
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type SensitiveFile struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	UniqueID      uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	Filepath      string `gorm:"-" json:"filepath"`
	Filename      string `gorm:"column:filename" json:"filename"`
	MD5           string `gorm:"column:md5" json:"md5"` // 文件内容的 MD5
	DescriptionEn string `gorm:"column:description_en" json:"descriptionEn"`
	DescriptionZh string `gorm:"column:description_zh" json:"descriptionZh"`
	CreatedAt     int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds

	DownloadFilename string       `gorm:"-" json:"downloadFilename"` // 下载的文件名，如果为空，说明文件不存在等，不能下载
	Layer            string       `gorm:"-" json:"layer"`            // 存在于镜像的那个层级
	PolicyDetect     PolicyDetect `gorm:"-" json:"policyDetect"`     // 对各个策略的检测结果
}

func (vi *SensitiveFile) TableName() string {
	return "ivan_scan_image_sensitive"
}

func (vi *SensitiveFile) GenDownloadFilename() string {

	split := strings.Split(vi.Filename, ".")
	if len(split) > 0 && split[0] != "" {
		df := split[0] + ".zip"
		vi.DownloadFilename = df
		return df
	}
	return ""
}

func (vi *SensitiveFile) GenFullFilename() string {
	return vi.Filepath + vi.Filename
}

func (vi *SensitiveFile) GenUniqueID() uint64 {
	key := fmt.Sprintf(UniqueSensitiveFormat, vi.Filename, vi.DescriptionEn, vi.DescriptionZh)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

func (vi *SensitiveFile) Same(after *SensitiveFile) bool {
	if vi.Filename != after.Filename || vi.DescriptionEn != after.DescriptionEn ||
		vi.DescriptionZh != after.DescriptionZh || vi.MD5 != vi.MD5 {
		return false
	}
	return true
}

func (vi *SensitiveFile) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.Filename == "" {
		return fmt.Errorf("not get Name")
	}
	if vi.MD5 == "" {
		return fmt.Errorf("not get MD5")
	}
	if vi.UniqueID == 0 {
		vi.UniqueID = vi.GenUniqueID()
	}
	if vi.UniqueID <= 0 {
		return fmt.Errorf("not get uniqueID")
	}
	return nil
}

func (vi *SensitiveFile) Deserialize(iss []*SensitiveToImage) {

	split := strings.Split(vi.Filename, "/")
	if len(split) == 0 || (len(split) == 1 && split[0] == "") {
		return
	}

	if len(split) > 0 {
		vi.Filepath = strings.Join(split[:len(split)-1], "/")
		vi.Filename = split[len(split)-1]
	}

	if vi.Filepath == "" {
		vi.Filepath = "/"
	}
	if !strings.HasPrefix(vi.Filepath, "/") {
		vi.Filepath = "/" + vi.Filepath
	}
	if !strings.HasSuffix(vi.Filepath, "/") {
		vi.Filepath = vi.Filepath + "/"
	}

	vi.DownloadFilename = vi.GenDownloadFilename()

	for i := range iss {
		if vi.UniqueID == iss[i].UniqueTarget {
			vi.Layer = iss[i].LayerDigest
			break
		}
	}
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
	if vi == nil {
		return ""
	}
	return "ivan_image_sensitive_issue"
}
