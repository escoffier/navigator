package model

import (
	"database/sql/driver"
	"time"

	json "github.com/json-iterator/go"
)

type Location struct {
	ClusterKey    string   `json:"cluster_key"`
	Type          string   `json:"type"`
	LocationElems []string `json:"location_elems"`
	Expr          string   `json:"expr"`
}

type Locations []Location

func (l Locations) Scan(value interface{}) error {
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
	ID              int64     `gorm:"column:id"`
	AssociationKind string    `gorm:"column:association_kind"`
	Locations       Locations `gorm:"column:locations; type:jsonb"`
	EventsNum       int64     `gorm:"column:events_num"`
	NodesNum        int64     `gorm:"column:nodes_num"`
	Severity        int32     `gorm:"column:severity"`
	CreatedAt       time.Time `gorm:"column:created_at"`
	UpdatedAt       time.Time `gorm:"column:updated_at"`
}

func (PalaceAssociatedGraphEvent) TableName() string {
	return "palace_assoc_graph_events"
}

type PalaceEventSignalAssociation struct {
	UUID      uint32    `gorm:"column:uuid"`
	AggrEvtID int64     `gorm:"column:aggr_evt_id"`
	AggrKey   string    `gorm:"column:aggr_key"`
	SignalID  string    `gorm:"column:signal"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

func (PalaceEventSignalAssociation) TableName() string {
	return "palace_evt_signal_assocs"
}

type PalaceAssociationLink struct {
	UUID           uint32    `gorm:"column:uuid"`
	AggrEvtID      int64     `gorm:"column:aggr_evt_id"`
	SrcClusterKey  string    `gorm:"column:src_cluster_key"`
	SrcLocType     string    `gorm:"column:src_loc_type"`
	SrcLocExpr     string    `gorm:"column:src_loc_expr"`
	DestClusterKey string    `gorm:"column:dest_cluster_key"`
	DestLocType    string    `gorm:"column:dest_loc_type"`
	DestLocExpr    string    `gorm:"column:dest_loc_expr"`
	CreatedAt      time.Time `gorm:"column:created_at"`
}

func (PalaceAssociationLink) TableName() string {
	return "palace_assoc_links"
}
