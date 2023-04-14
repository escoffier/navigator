package model

import (
	"time"

	json "github.com/json-iterator/go"
)

type PodInfo struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	PodName   string `json:"name"`
}

type ProcessingRecord struct {
	ID         string   `json:"-"`
	EventID    int64    `json:"eventID"`
	OpType     string   `json:"opType"`
	UpdatedAt  int64    `json:"updatedAt"`
	Status     string   `json:"status"`
	LastOpUser string   `json:"lastOpUser"`
	Object     []string `json:"object"`
}

type ProcessingRecordChange struct {
	ID         string
	UpdatedAt  int64
	Status     string
	LastOpUser string
}

type ProcessingAction struct {
	ID        int32     `gorm:"column:id"` // 自增主键
	Object    string    `gorm:"column:object"`
	RecordID  string    `gorm:"column:record_id; index:idx_processingcenter_actions_record_id"` // 添加索引
	Operation string    `gorm:"column:operation"`
	Creator   string    `gorm:"column:creator"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

func (p *ProcessingAction) GetObjects() []string {
	var result []string
	_ = json.Unmarshal([]byte(p.Object), &result)
	return result
}

func (p *ProcessingAction) SetObject(objects []string) {
	jsonBytes, _ := json.Marshal(objects)
	p.Object = string(jsonBytes)
}

func (ProcessingAction) TableName() string {
	return "ivan_platform_processingcenter_actions"
}

type ObjectDisplay struct {
	Key    string `json:"key"`
	Status string `json:"status"`
}

type ActionDisplay struct {
	RecordID  string   `json:"recordID"`
	Action    string   `json:"action"`
	User      string   `json:"user"`
	Object    []string `json:"object"`
	Timestamp int64    `json:"timestamp"`
}

type ProcessingRecordDisplay struct {
	ID         string           `json:"id"`
	EventID    int64            `json:"eventID,string"`
	OpType     string           `json:"opType"`
	Status     string           `json:"status"`
	LastOpUser string           `json:"lastOpUser"`
	Object     []*ObjectDisplay `json:"object"`
	UpdatedAt  int64            `json:"updatedAt"`
	Actions    []*ActionDisplay `json:"actions"`
}

type QueryProcessingRecordArg struct {
	ID             string
	Filter         map[string]string
	StartTimestamp int64
	EndTimestamp   int64
	Offset         int
	Limit          int
}
