package model

type ExportTask struct {
	Status     uint8  `gorm:"column:status"`
	CheckType  string `gorm:"type:varchar(255);column:check_type"`
	ClusterId  string `gorm:"type:varchar(255);column:cluster_id"`
	CheckId    string `gorm:"type:varchar(255);column:task_id"`
	FileName   string `gorm:"type:varchar(255);column:filename"`
	UserName   string `gorm:"type:varchar(255);column:username"`
	CreatedAt  int64  `gorm:"column:created_at"`
	FinishedAt int64  `gorm:"column:finished_at"`
	Content    []byte `gorm:"type:mediumBlob;column:content"`
}

func (ExportTask) TableName() string {
	return "ivan_scanner_scan_export_task"
}

type ScapRetData struct {
	NodeName    string `xlsx:"0"`
	PolicyId    string `xlsx:"1"`
	Classified  string `xlsx:"2"`
	Section     string `xlsx:"3"`
	Descript    string `xlsx:"4"`
	DecDetail   string `xlsx:"5"`
	LastTime    string `xlsx:"6"`
	Status      string `xlsx:"7"`
	TestResult  string `xlsx:"8"`
	Audit       string `xlsx:"9"`
	Remediation string `xlsx:"10"`
}

func GetStatusZh(status ScapScanResultStateType) string {
	var ret string
	switch status {
	case ScapScanResultStateFAIL:
		ret = "未通过"
	case ScapScanResultStateWARN:
		ret = "警告"
	case ScapScanResultStatePASS:
		ret = "通过"
	case ScapScanResultStateINFO:
		ret = "忽略"
	default:
		ret = "未知: " + string(status)
	}
	return ret
}

func GetTitleZh() *ScapRetData {
	return &ScapRetData{
		NodeName:    "节点",
		PolicyId:    "合规 ID",
		Classified:  "等保对齐",
		Section:     "合规条目",
		Descript:    "具体要求",
		DecDetail:   "详情",
		LastTime:    "最后扫描时间",
		Status:      "状态",
		TestResult:  "检测结果",
		Audit:       "验证方法",
		Remediation: "修复建议",
	}
}
