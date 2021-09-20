package conf

type DumpItem struct {
	Name      string `json:"name"`
	TimeField string `json:"timeField"`
	DataDir   string `json:"dataDir"`
	Batch     int64  `json:"batch"`
}

type PGDumpItem struct {
	DumpItem
	PrimaryKey []string `json:"primaryKey"`
	Condition  string   `json:"condition"`
	TTL        int32    `json:"ttl"`
}
type DumpLogicConf struct {
	PGTables         []*PGDumpItem  `json:"pgTables"`
	MongoUnifiedConf *MongoDumpConf `json:"mongoUnifiedConf"`
}

type MongoDumpConf struct {
	ExcludedCollections []string `json:"excludedCollections"`
	Batch               int64    `json:"batch"`
	BaseDir             string   `json:"baseDir"`
	TimeField           string   `json:"timeField"`
}

type OfflineConf struct {
	ESDumpItems []*ESDumpItem `json:"esDumpItems"`
}

type ESDumpItem struct {
	IndexPrefix string `json:"indexPrefix"`
	TTL         int32  `json:"ttl"`
}
