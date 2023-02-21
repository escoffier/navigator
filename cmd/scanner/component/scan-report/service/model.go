package service

type SearchExportTaskParam struct {
	Finished     string
	Failure      string
	ExecuteType  []string
	NeedCiReport string
}

type GetExportTaskParam struct {
	ID   int64
	UUID string
}
