package imagesec

import (
	"time"
)

type SearchExportVulnDuplicateParam struct {
	TaskID      int64
	UniqueVulns []uint64
	UseType     int64
	Filter      *Filter
}

type SearchExportTaskParam struct {
	ExecuteType     []string
	TaskType        string
	Parameter       string
	Finished        string
	Failure         string
	ID              int64
	NotIds          []int64
	ExpirationDate  time.Time
	ExportHtmlReady string
	NeedCiReport    string
	Filter          *Filter
}

type SearchExportTaskImageParam struct {
	TaskID   int64
	StartID  int64
	ImageIds []int64
	Filter   *Filter
}

type SearchHtmlVulnImageParam struct {
	TaskID      int64
	UniqueVulns []uint64
	CanFixed    string
	Severity    int64
	Fields      []string
	StartID     int64
	Filter      *Filter
}
