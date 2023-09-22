package model

import (
	"database/sql/driver"
	"fmt"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/security-rd/go-pkg/pb"
)

const (
	MQTopicPalacePodContainerEvents = "ivan_podcontainer_events"
)

type Location struct {
	ClusterKey    string   `json:"cluster_key"`
	Type          string   `json:"type"`
	LocationElems []string `json:"location_elems"`
	Expr          string   `json:"expr"`
}

type Locations []Location

func (l *Locations) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &l)
}
func (l Locations) Value() (driver.Value, error) {
	return json.Marshal(l)
}

type PalaceAssociatedGraphEvent struct {
	ID              uint64    `gorm:"column:id"`
	AssociationKind string    `gorm:"column:association_kind"`
	Locations       Locations `gorm:"column:locations; type:jsonb"`
	EventsNum       int       `gorm:"column:events_num"`
	NodesNum        int       `gorm:"column:nodes_num"`
	Severity        uint32    `gorm:"column:severity"`
	CreatedAt       time.Time `gorm:"column:created_at"`
	UpdatedAt       time.Time `gorm:"column:updated_at"`
}

func (PalaceAssociatedGraphEvent) TableName() string {
	return "ivan_palace_assoc_graph_events"
}

type PalaceEventSignalAssociation struct {
	UUID      uint64    `gorm:"column:uuid"`
	AggrEvtID uint64    `gorm:"column:aggr_evt_id"`
	AggrKey   string    `gorm:"column:aggr_key"`
	SignalID  string    `gorm:"column:signal_id"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

func (PalaceEventSignalAssociation) TableName() string {
	return "ivan_palace_evt_signal_assocs"
}

type PalaceAssociationLink struct {
	UUID           uint64    `gorm:"column:uuid"`
	AggrEvtID      uint64    `gorm:"column:aggr_evt_id"`
	SrcClusterKey  string    `gorm:"column:src_cluster_key"`
	SrcLocType     string    `gorm:"column:src_loc_type"`
	SrcLocExpr     string    `gorm:"column:src_loc_expr"`
	DestClusterKey string    `gorm:"column:dest_cluster_key"`
	DestLocType    string    `gorm:"column:dest_loc_type"`
	DestLocExpr    string    `gorm:"column:dest_loc_expr"`
	Context        string    `gorm:"column:context"`
	CreatedAt      time.Time `gorm:"column:created_at"`
}

func (PalaceAssociationLink) TableName() string {
	return "ivan_palace_assoc_links"
}

type Signal struct {
	ID           string                `json:"-"`
	UUID         int64                 `json:"uuid"`
	Cluster      string                `json:"cluster"`
	Namespace    string                `json:"namespace"`
	NodeType     string                `json:"nodeType"`
	NodeKey      string                `json:"nodeKey"`
	RuleName     string                `json:"ruleName"`
	RuleCategory string                `json:"ruleCategory"`
	RuleModule   string                `json:"ruleModule"`
	Severity     uint8                 `json:"severity"`
	PodUID       string                `json:"podUid"`
	PodName      string                `json:"podName"`
	CustomKV     []*pb.MultiLanguageKV `json:"customKV"`
	Extend       *SignalExtend         `json:"extend,omitempty"`
	Timestamp    int64                 `json:"timestamp"`
}

type SignalExtend struct {
	Hid      string `json:"hid,omitempty"`
	HThreats string `json:"hThreats,omitempty"`
}

type CustomKVs []*pb.MultiLanguageKV

func (l *CustomKVs) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &l)
}
func (l CustomKVs) Value() (driver.Value, error) {
	return json.Marshal(l)
}

type LangKV struct {
	ValueHash map[string]string `json:"ValueHash"`
}

type MultiLanguage map[string]LangKV

func (l *MultiLanguage) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &l)
}
func (l MultiLanguage) Value() (driver.Value, error) {
	return json.Marshal(l)
}

type Tags []string

func (t *Tags) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("gorm.Scan failed to assert Tags: %v", value)
	}
	if len(bytes) == 0 {
		bytes = []byte("[]")
	}

	result := Tags{}
	err := json.Unmarshal(bytes, &result)
	*t = result
	return err
}

func (t Tags) Value() (driver.Value, error) {
	bt := make([]byte, 0)
	if t == nil {
		return bt, nil
	}

	bt, err := json.Marshal(t)
	if err != nil {
		return bt, nil
	}
	return bt, nil
}

type EvtCenterRule struct {
	ID            int32         `gorm:"primaryKey; autoIncrement; column:id"`
	Version1      string        `gorm:"column:version1; size:32"`
	Name          string        `gorm:"uniqueIndex:rules_key; column:name; size:255"`
	Module        string        `gorm:"uniqueIndex:rules_key; column:module; size:32"`
	Category      string        `gorm:"uniqueIndex:rules_key; column:category; size:32"`
	Description   string        `gorm:"column:description"`
	Severity      uint32        `gorm:"column:severity"`
	CustomKV      CustomKVs     `gorm:"column:custom_kv"`
	MultiLanguage MultiLanguage `gorm:"column:multi_language"`
	Status        uint8         `gorm:"column:status"`
	Tags          Tags          `gorm:"column:tags"`
}

func (EvtCenterRule) TableName() string {
	return "ivan_eventcenter_rules"
}
