package conf

type DumpItem struct {
	Name      string `json:"name"`
	TimeField string `json:"timeField"`
	DataDir   string `json:"dataDir"`
	Batch     int64  `json:"batch"`
}

type RDBDumpItem struct {
	DumpItem
	PrimaryKey []string `json:"primaryKey"`
	Condition  string   `json:"condition"`
	TTL        int32    `json:"ttl"`
}
type DumpLogicConf struct {
	Tables []*RDBDumpItem `json:"tables"`
}

type OfflineConf struct {
	ESDumpItems []*ESDumpItem `json:"esDumpItems"`
}

type ESDumpItem struct {
	IndexPrefix string     `json:"indexPrefix"`
	TTL         int32      `json:"ttl"`
	Condition   *Condition `json:"condition"`
}

type Condition struct {
	Filter string `json:"filter"`
}
