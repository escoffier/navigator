package model

import (
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ImageRecord struct {
	ID             int64                       `json:"id"`
	ProjectUuid    string                      `json:"projectUuid"` // portal项目的Project.Uuid关联
	ImageName      string                      `json:"imageName"`
	VulnStatic     imagesec.VulnSeverityStatic `json:"vulnStatic"` // 漏洞统jj
	Questions      []string                    `json:"questions"`
	TaskName       string                      `json:"pipelineName"`
	ScanTime       int64                       `json:"scanTime"`
	InWhitelist    bool                        `json:"inWhitelist"`
	MatchWhitelist bool                        `json:"matchWhitelist"`
	Status         string                      `json:"status"`
}
