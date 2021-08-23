package conf

type DumpItem struct {
	Name      string `json:"name"`
	TimeField string `json:"timeField"`
	Condition string `json:"condition"`
	DataDir   string `json:"dataDir"`
	Batch     int64  `json:"batch"`
}

type DumpLogicConf struct {
	PGTables         []*DumpItem    `json:"pgTables"`
	MongoUnifiedConf *MongoDumpConf `json:"mongoUnifiedConf"`
}

type MongoDumpConf struct {
	ExcludedCollections []string `json:"excludedCollections"`
	Batch               int64    `json:"batch"`
	BaseDir             string   `json:"baseDir"`
	TimeField           string   `json:"timeField"`
}

type OfflineConf struct {
	ESIndexPrefixes []string `json:"esIndexPrefixes"`
}
