package imagesec

import (
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type License struct {
	ID        int64  `gorm:"primaryKey" json:"id"`
	UniqueID  uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	Name      string `gorm:"column:name" json:"name"`
	MD5       string `gorm:"md5" json:"md5"`
	Content   string `gorm:"column:content" json:"content"`
	Filename  string `gorm:"column:filename" json:"filename"`
	CreatedAt int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds

	PolicyDetect     PolicyDetect `gorm:"-" json:"policyDetect"` // 对各个策略的检测结果
	Filepath         string       `gorm:"-" json:"filepath"`
	DownloadFilename string       `gorm:"-" json:"downloadFilename"`
	Layer            string       `gorm:"-" json:"layer"` // 存在于镜像的那个层级
}

func (vi *License) TableName() string {
	return "ivan_scan_image_license"
}

func (vi *License) GenDownloadFilename() string {
	split := strings.Split(vi.Name, ".")
	if len(split) > 0 && split[0] != "" {
		df := split[0] + ".zip"
		vi.DownloadFilename = df
		return df
	}
	return ""
}

func (vi *License) Same(after *License) bool {
	if vi.Filename != after.Filename || vi.Name != after.Name || vi.MD5 != after.MD5 {
		return false
	}
	return true
}

func (vi *License) Check() error {
	if vi == nil {
		return fmt.Errorf("not get model")
	}
	if vi.Name == "" {
		return fmt.Errorf("not get name")
	}
	if vi.Filename == "" {
		return fmt.Errorf("not get filename")
	}
	// if vi.MD5 == "" {
	// 	return fmt.Errorf("not get MD5")
	// }
	return nil
}

func (vi *License) GenUniqueID() uint64 {
	key := fmt.Sprintf("%s-%s-%s", vi.Filename, vi.MD5, vi.Name)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

func (vi *License) Deserialize() {

	split := strings.Split(vi.Filename, "/")

	if len(split) == 0 || (len(split) == 1 && split[0] == "") {
		return
	}

	if len(split) > 0 {
		vi.Filename = split[len(split)-1]
		vi.Filepath = strings.Join(split[:len(split)-1], "/")
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
}

func (vi *License) Serialize() {
	if vi.UniqueID <= 0 {
		vi.UniqueID = vi.GenUniqueID()
	}
	vi.Content = ""
}

type LicenseToImage struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	UniqueID      uint64 `gorm:"column:unique_id" json:"uniqueID,string"` // 数据库的中唯一建，去重效率高
	UniqueTarget  uint64 `gorm:"column:unique_target" json:"uniqueTarget,string"`
	ImageUniqueID uint64 `gorm:"column:image_unique_id" json:"imageUniqueID,string"`
	LayerDigest   string `gorm:"column:layer_digest" json:"layerDigest"`
	CreatedAt     int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *LicenseToImage) GenUniqueID() uint64 {
	key := fmt.Sprintf("%d-%d-%s", vi.ImageUniqueID, vi.UniqueTarget, vi.LayerDigest)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

func (vi *LicenseToImage) Same(after *LicenseToImage) bool {
	if vi.LayerDigest != after.LayerDigest || vi.ImageUniqueID != after.ImageUniqueID ||
		vi.UniqueTarget != after.UniqueTarget {
		return false
	}
	return true
}

func (vi *LicenseToImage) TableName() string {
	if vi == nil {
		return ""
	}
	return "ivan_image_license_issue"
}
