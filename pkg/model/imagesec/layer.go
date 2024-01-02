package imagesec

import (
	"encoding/json"
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	MalwareCacheData   = "malware"
	SensitiveCacheData = "sensitive"
	WebshellCacheData  = "webshell"
	LicenseCacheData   = "license"
)

type ScanLayerData struct {
	ID        int64  `gorm:"column:id" json:"id"`
	UniqueID  uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	Layer     string `gorm:"column:layer" json:"layer"`
	Issue     string `gorm:"column:issue" json:"issue"`
	DbVersion string `gorm:"column:db_version" json:"dbVersion"`
	DataJson  string `gorm:"column:data" json:"-"`                                    //
	CreatedAt int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds

	LicenseUnique   []uint64 `gorm:"-" json:"licenseUnique"`
	SensitiveUnique []uint64 `gorm:"-" json:"sensitiveUnique"`
	WebshellUnique  []uint64 `gorm:"-" json:"webshellUnique"`
	MalwareUnique   []uint64 `gorm:"-" json:"malwareUnique"`

	License   []*License       `gorm:"-" json:"license"`
	Sensitive []*SensitiveFile `gorm:"-" json:"sensitive"`
	Webshell  []*Webshell      `gorm:"-" json:"hmWebshell"`
	Malware   []*Malware       `gorm:"-" json:"aviraMalware"`
}

type ScanCache struct {
	License       []License
	SensitiveFile []SensitiveFile
	Webshell      []Webshell
	Malware       []Malware
}

func (vi *ScanLayerData) GenLayerFile() []*LayerFile {
	res := make([]*LayerFile, 0)
	for _, mal := range vi.Malware {
		if vi.UniqueID <= 0 || mal.Hash == "" {
			continue
		}
		res = append(res, &LayerFile{
			LayerUniqueID: vi.UniqueID,
			FileMD5:       mal.Hash,
		})
	}
	for _, mal := range vi.Sensitive {
		if vi.UniqueID <= 0 || mal.MD5 == "" {
			continue
		}
		res = append(res, &LayerFile{
			LayerUniqueID: vi.UniqueID,
			FileMD5:       mal.MD5,
		})
	}
	for _, mal := range vi.Webshell {
		if vi.UniqueID <= 0 || mal.MD5 == "" {
			continue
		}
		res = append(res, &LayerFile{
			LayerUniqueID: vi.UniqueID,
			FileMD5:       mal.MD5,
		})
	}
	for _, mal := range vi.License {
		if vi.UniqueID <= 0 || mal.MD5 == "" {
			continue
		}
		res = append(res, &LayerFile{
			LayerUniqueID: vi.UniqueID,
			FileMD5:       mal.MD5,
		})
	}

	return res
}

func (vi *ScanLayerData) GenUniqueID() uint64 {
	uid := util.GenerateUUID64(fmt.Sprintf("%s-%s-%s", vi.Issue, vi.Layer, vi.DbVersion))
	return uid
}

func (vi *ScanLayerData) SetEmpty() {
	if len(vi.License) == 0 {
		vi.License = make([]*License, 0)
	}
	if len(vi.Malware) == 0 {
		vi.Malware = make([]*Malware, 0)
	}
	if len(vi.Webshell) == 0 {
		vi.Webshell = make([]*Webshell, 0)
	}

	if len(vi.Sensitive) == 0 {
		vi.Sensitive = make([]*SensitiveFile, 0)
	}

	if len(vi.LicenseUnique) == 0 {
		vi.LicenseUnique = make([]uint64, 0)
	}
	if len(vi.MalwareUnique) == 0 {
		vi.MalwareUnique = make([]uint64, 0)
	}
	if len(vi.WebshellUnique) == 0 {
		vi.WebshellUnique = make([]uint64, 0)
	}

	if len(vi.SensitiveUnique) == 0 {
		vi.SensitiveUnique = make([]uint64, 0)
	}
}

func (vi *ScanLayerData) Check() error {
	if vi.Layer == "" {
		return fmt.Errorf("not get layer")
	}
	if vi.Issue == "" {
		return fmt.Errorf("not get issue")
	}
	if vi.DbVersion == "" {
		return fmt.Errorf("not get dbVersion")
	}

	return nil
}

func (vi *ScanLayerData) Same(after *ScanLayerData) bool {
	return vi.UniqueID == after.UniqueID && vi.DataJson == after.DataJson
}

func (vi *ScanLayerData) TableName() string {
	return "ivan_scan_data_layer"
}

func (vi *ScanLayerData) Deserialize(container *ScanLayerData) {

	if !strings.HasPrefix(vi.Layer, "sha256:") {
		vi.Layer = fmt.Sprintf("sha256:%s", vi.Layer)
	}

	switch vi.Issue {

	case WebshellCacheData:
		ss := make([]uint64, 0)
		if err := json.Unmarshal([]byte(vi.DataJson), &ss); err == nil {
			vi.WebshellUnique = ss
		}

	case MalwareCacheData:
		ss := make([]uint64, 0)
		if err := json.Unmarshal([]byte(vi.DataJson), &ss); err == nil {
			vi.MalwareUnique = ss
		}
	case SensitiveCacheData:
		ss := make([]uint64, 0)
		if err := json.Unmarshal([]byte(vi.DataJson), &ss); err == nil {
			vi.SensitiveUnique = ss
		}
	case LicenseCacheData:
		ss := make([]uint64, 0)
		if err := json.Unmarshal([]byte(vi.DataJson), &ss); err == nil {
			vi.LicenseUnique = ss
		}
	}

	if container != nil {
		for _, ml := range vi.MalwareUnique {
			for j := range container.Malware {
				if ml == container.Malware[j].UniqueID {
					vi.Malware = append(vi.Malware, container.Malware[j])
				}
			}
		}

		for _, ml := range vi.SensitiveUnique {
			for j := range container.Sensitive {
				if ml == container.Sensitive[j].UniqueID {
					vi.Sensitive = append(vi.Sensitive, container.Sensitive[j])
				}
			}
		}

		for _, ml := range vi.LicenseUnique {
			for j := range container.License {
				if ml == container.License[j].UniqueID {
					vi.License = append(vi.License, container.License[j])
				}
			}
		}
		for _, ml := range vi.WebshellUnique {
			for j := range container.Webshell {
				if ml == container.Webshell[j].UniqueID {
					vi.Webshell = append(vi.Webshell, container.Webshell[j])
				}
			}
		}
	}

	for i := range vi.Malware {
		vi.Malware[i].Layer = vi.Layer
	}

	for i := range vi.Webshell {
		vi.Webshell[i].Layer = vi.Layer
	}
	for i := range vi.License {
		vi.License[i].Layer = vi.Layer
	}
	for i := range vi.Sensitive {
		vi.Sensitive[i].Layer = vi.Layer
	}

	vi.SetEmpty()
}

func (vi *ScanLayerData) Serialize() {

	if strings.Contains(vi.Layer, "sha256:") {
		vi.Layer = strings.TrimPrefix(vi.Layer, "sha256:")
	}

	vi.SetEmpty()

	for j := range vi.Webshell {
		vi.WebshellUnique = append(vi.WebshellUnique, vi.Webshell[j].UniqueID)
	}
	for j := range vi.Sensitive {
		vi.SensitiveUnique = append(vi.SensitiveUnique, vi.Sensitive[j].UniqueID)
	}
	for j := range vi.Malware {
		vi.MalwareUnique = append(vi.MalwareUnique, vi.Malware[j].UniqueID)
	}
	for j := range vi.License {
		vi.LicenseUnique = append(vi.LicenseUnique, vi.License[j].UniqueID)
	}

	vi.WebshellUnique = util.DuplicateUint64Slice(vi.WebshellUnique)
	vi.SensitiveUnique = util.DuplicateUint64Slice(vi.SensitiveUnique)
	vi.MalwareUnique = util.DuplicateUint64Slice(vi.MalwareUnique)
	vi.LicenseUnique = util.DuplicateUint64Slice(vi.LicenseUnique)

	switch vi.Issue {

	case WebshellCacheData:
		if bys, err := json.Marshal(vi.WebshellUnique); err == nil {
			vi.DataJson = string(bys)
		}

	case MalwareCacheData:
		if bys, err := json.Marshal(vi.MalwareUnique); err == nil {
			vi.DataJson = string(bys)
		}
	case SensitiveCacheData:
		if bys, err := json.Marshal(vi.SensitiveUnique); err == nil {
			vi.DataJson = string(bys)
		}
	case LicenseCacheData:
		if bys, err := json.Marshal(vi.LicenseUnique); err == nil {
			vi.DataJson = string(bys)
		}
	}
	vi.UniqueID = vi.GenUniqueID()
}

type LayerFile struct {
	ID            int64  `gorm:"column:id" json:"id"`
	UniqueID      uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	LayerUniqueID uint64 `gorm:"column:layer_unique_id" json:"layerUniqueID,string"`
	FileMD5       string `gorm:"column:file_md5" json:"fileMD5"`
	CreatedAt     int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *LayerFile) TableName() string {
	return "ivan_scan_file_layer"
}

func (vi *LayerFile) Check() error {
	if vi.LayerUniqueID <= 0 {
		return fmt.Errorf("not get LayerUniqueID")
	}
	if vi.FileMD5 == "" {
		return fmt.Errorf("not get FileMD5")
	}

	return nil
}

func (vi *LayerFile) Same(after *LayerFile) bool {
	return vi.UniqueID == after.UniqueID
}

func (vi *LayerFile) Serialize() {
	vi.UniqueID = vi.GenUniqueID()
}

func (vi *LayerFile) GenUniqueID() uint64 {
	uid := util.GenerateUUID64(fmt.Sprintf("%s-%d", vi.FileMD5, vi.LayerUniqueID))
	return uid
}
