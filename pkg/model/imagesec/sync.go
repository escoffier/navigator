package imagesec

import (
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageSyncTask struct {
	ID          int64               `gorm:"primaryKey" json:"id"`
	RegistryID  int64               `gorm:"column:registry_id" json:"registryID"`
	SyncType    string              `gorm:"column:sync_type" json:"syncType"`
	StartAt     int64               `gorm:"column:start_at" json:"startAt"`   // 开始时间
	FinishAt    int64               `gorm:"column:finish_at" json:"finishAt"` // 完成时间
	Result      string              `gorm:"column:result" json:"result"`
	CreatedAt   int64               `gorm:"autoCreateTime:milli" json:"createdAt"`
	Registry    Registry            `gorm:"-" json:"registry"`
	ScanInsInfo ScannerInstanceInfo `gorm:"-" json:"scanInsInfo"`
}

func (*ImageSyncTask) TableName() string {
	return "ivan_scanner_sync_tasks"
}

type SearchRegistryParam struct {
	RegIds          []int64
	Fields          []string // 只想要的字端
	LibraryURL      string
	RegType         []string
	ID              int64
	NameKeyword     string
	UrlKeyword      string
	Status          []string
	Name            string
	StartSyncAt     int64
	EndSyncAt       int64
	Deleted         string
	ScannerInstance string
	Filter          *Filter
}

func (s *SearchRegistryParam) Compatible() {
	s.RegType = util.DuplicateStringSlice(s.RegType)
	for i := range s.RegType {
		if s.RegType[i] == HarborVersion {
			s.RegType = append(s.RegType, HarborV2Version, HarborV1Version)
		}
	}
}

type SearchSyncTaskParam struct {
	TaskID   int64
	RegIds   []int64
	Finished string
	SyncType string
	Filter   *Filter
}
