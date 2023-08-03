package model

import (
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
)

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
	Runtime     string
}

func GetStatus(language lang.LanguageType, status ScapScanResultStateType) string {
	var ret string
	switch status {
	case ScapScanResultStateFAIL:
		if language == lang.LanguageEN {
			ret = "NotPass"
		} else {
			ret = "未通过"
		}
	case ScapScanResultStateWARN:
		if language == lang.LanguageEN {
			ret = "Warn"
		} else {
			ret = "警告"
		}
	case ScapScanResultStatePASS:
		if language == lang.LanguageEN {
			ret = "Pass"
		} else {
			ret = "通过"
		}
	case ScapScanResultStateINFO:
		if language == lang.LanguageEN {
			ret = "Ignore"
		} else {
			ret = "忽略"
		}
	default:
		if language == lang.LanguageEN {
			ret = "Unknown"
		} else {
			ret = "未知"
		}
		ret += string(": " + status)
	}
	return ret
}

func GetTitle(language lang.LanguageType, checkType string) *ScapRetData {
	runtime := ""
	if ComplianceCheckType(checkType) == ComplianceCheckTargetTypeDocker {
		if language == lang.LanguageEN {
			runtime = "Runtime Type"
		} else {
			runtime = "运行时类型"
		}
	}

	if language == lang.LanguageEN {
		return &ScapRetData{
			NodeName:    "Node",
			PolicyId:    "Compliance ID",
			Classified:  "Dengbao",
			Section:     "Compliance Policies",
			Descript:    "Rule requirements",
			DecDetail:   "Detail",
			LastTime:    "Last Time",
			Status:      "Status",
			TestResult:  "Test Result",
			Audit:       "Audit",
			Remediation: "Remediation",
			Runtime:     runtime,
		}
	}

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
		Runtime:     runtime,
	}
}
