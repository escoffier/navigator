package imagesec

import (
	"encoding/json"
	"fmt"
	"os"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 软件包
type Pkg struct {
	ID            int64        `gorm:"primaryKey" json:"id"`
	UniqueID      uint64       `gorm:"column:unique_id" json:"uniqueID,string"`
	Name          string       `gorm:"column:name" json:"name"`
	Version       string       `gorm:"column:version" json:"version"`
	OSFamily      string       `gorm:"column:os_family" json:"osFamily"`
	OSName        string       `gorm:"column:os_name" json:"osName"`
	PkgType       string       `gorm:"column:pkg_type" json:"pkgType"` // jar,pip,jar-pkg,python-pkg,对应原业漏洞表中namespace
	SrcName       string       `gorm:"column:src_name" json:"srcName"`
	SrcVersion    string       `gorm:"column:src_version" json:"srcVersion"`
	LicenseJson   string       `gorm:"column:license" json:"-"`
	License       []string     `gorm:"-" json:"license"`
	DependsOnJSON string       `gorm:"column:depends_on" json:"-"`
	DependsOn     []string     `gorm:"-" json:"dependsOn"`
	Filepath      string       `gorm:"column:filepath" json:"filepath"`
	Class         string       `gorm:"class" json:"class"`
	Flag          uint64       `gorm:"column:flag" json:"flag,string"`
	CreatedAt     int64        `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt     int64        `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
	PolicyDetect  PolicyDetect `gorm:"-" json:"policyDetect"`                                   // 对各个策略的检测结果
}

func (vi *Pkg) GenKernelVuln() bool {
	kernelVuln := os.Getenv("IDENTITY_KERNEL_VULN")
	// 提供开关临时关闭内核漏洞的判断
	if kernelVuln == consts.FalseString {
		return false
	}
	if util.ExistBit1(vi.Flag, VulnFlagKernelPkg) {
		return true
	}
	return false
}

func (vi *Pkg) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.Name == "" {
		return fmt.Errorf("not get Name")
	}
	if vi.Version == "" {
		return fmt.Errorf("not get Version")
	}

	if vi.UniqueID == 0 {
		vi.UniqueID = vi.GenUniqueID()
	}
	if vi.UniqueID <= 0 {
		return fmt.Errorf("not get uniqueID")
	}
	return nil
}

func (vi *Pkg) GenUniqueID() uint64 {
	key := fmt.Sprintf(UniquePkgFormat, vi.Name, vi.Version, vi.OSFamily, vi.OSName)
	uid := util.GenerateUUID64(key)
	return uid
}

func (vi *Pkg) TableName() string {
	return "ivan_scan_image_pkg"
}

func (vi *Pkg) Same(after *Pkg) bool {
	if vi.Name != after.Name || vi.Version == after.Version || vi.LicenseJson != after.LicenseJson ||
		vi.SrcName != after.SrcName || vi.SrcVersion != after.SrcVersion {
		return false
	}
	return true
}

func (vi *Pkg) Deserialize() {
	vi.License = make([]string, 0)
	if vi.LicenseJson != "" {
		li := make([]string, 0)
		if err := json.Unmarshal([]byte(vi.LicenseJson), &li); err == nil {
			for i := range li {
				if li[i] != "" {
					vi.License = append(vi.License, li[i])
				}
			}
		}
	}

	vi.DependsOn = make([]string, 0)
	if vi.DependsOnJSON != "" {
		li := make([]string, 0)
		if err := json.Unmarshal([]byte(vi.DependsOnJSON), &li); err == nil {
			vi.DependsOn = li
		}
	}
}

func (vi *Pkg) Serialize() {
	if len(vi.License) > 0 {
		if bys, err := json.Marshal(vi.License); err == nil {
			vi.LicenseJson = string(bys)
		}
	}
	if len(vi.DependsOn) > 0 {
		if bys, err := json.Marshal(vi.DependsOn); err == nil {
			vi.DependsOnJSON = string(bys)
		}
	}
}

type PkgToImage struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	UniqueID      uint64 `gorm:"column:unique_id" json:"uniqueID,string"` // 数据库的中唯一建，去重效率高
	UniqueTarget  uint64 `gorm:"column:unique_target" json:"uniqueTarget,string"`
	ImageUniqueID uint64 `gorm:"column:image_unique_id" json:"imageUniqueID,string"`
	LayerDigest   string `gorm:"column:layer_digest" json:"layerDigest"`
	CreatedAt     int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *PkgToImage) GenUniqueID() uint64 {
	if vi.UniqueID > 0 {
		return vi.UniqueID
	}
	key := fmt.Sprintf("%d-%d-%s", vi.ImageUniqueID, vi.UniqueTarget, vi.LayerDigest)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

func (vi *PkgToImage) Same(after *PkgToImage) bool {
	if vi.LayerDigest != after.LayerDigest || vi.ImageUniqueID != after.ImageUniqueID ||
		vi.UniqueTarget != after.UniqueTarget {
		return false
	}
	return true
}

func (vi *PkgToImage) TableName() string {
	// 由于仓库镜像，节点镜像，CI镜像的数据结构一致，但是数据量较大，所以要做分表处理
	if vi == nil {
		return ""
	}
	return "ivan_image_pkg_issue"
}
