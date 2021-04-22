package model

type ExportTask struct {
	Status     uint8  `json:"status" bson:"status"`
	CheckType  string `json:"checkType" bson:"checkType"`
	ClusterId  string `json:"clusterId" bson:"clusterId"`
	CheckId    string `json:"checkId" bson:"checkId"`
	FileName   string `josn:"filename" bson:"filename"`
	UserName   string `json:"username" bson:"username"`
	CreatedAt  int64  `json:"createdAt" bson:"createdAt"`
	FinishedAt int64  `json:"finishedAt" bson:"finishedAt"`
}

type ScapRetData struct {
	NodeName   string `xlsx:"0"`
	PolicyId   string `xlsx:"1"`
	Classified string `xlsx:"2"`
	Section    string `xlsx:"3"`
	Descript   string `xlsx:"4"`
	DecDetail  string `xlsx:"5"`
	LastTime   string `xlsx:"6"`
	Status     string `xlsx:"7"`
	Reason     string `xlsx:"8"`
}

func GetStatusZh(status string) string {
	var ret string
	switch status {
	case "FAIL":
		ret = "不合规"
	case "WARN":
		ret = "警告"
	case "PASS":
		ret = "合规"
	case "INFO":
		ret = "未知"
	default:
		ret = "未知"
	}
	return ret
}

func GetTitleZh() *ScapRetData {
	return &ScapRetData{
		NodeName:   "节点",
		PolicyId:   "合规 ID",
		Classified: "等保对齐",
		Section:    "合规条目",
		Descript:   "具体要求",
		DecDetail:  "详情",
		LastTime:   "最后扫描时间",
		Status:     "状态",
		Reason:     "未通过原因",
	}
}

func GetTitleEn() *ScapRetData {
	return &ScapRetData{
		NodeName:   "Status Name",
		PolicyId:   "Policy no",
		Classified: "Dengbao 2.0",
		Section:    "Type",
		Descript:   "Description",
		DecDetail:  "Details",
		LastTime:   "Last scan time",
		Status:     "Status",
		Reason:     "Reason for failure",
	}
}
