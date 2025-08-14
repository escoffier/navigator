package model

import (
	"fmt"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/portalI18"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type SearchVulnParam struct {
	ProjectUuid     string   `json:"projectUuid"`
	CodesecUuid     string   `json:"codesecUuid"`
	SourceCheckUuid string   `json:"sourceCheckUuid"`
	UniqueIds       []uint64 `json:"uniqueIds"`
	StartID         int64    `json:"startID"`
	Filter          *imagesec.Filter
}

func (s *SearchVulnParam) Check() error {
	if s.ProjectUuid == "" {
		return portalI18.ProjectUuidRequired(fmt.Errorf("project_uuid is required"))
	}
	return nil
}

type SearchScanResultParam struct {
	ProjectUuid     string `json:"projectUuid"`
	CodesecUuid     string `json:"codesecUuid"`
	SourceCheckUuid string `json:"sourceCheckUuid"`
}

func (s *SearchScanResultParam) Check() error {
	if s.ProjectUuid == "" {
		return portalI18.ProjectUuidRequired(fmt.Errorf("project_uuid is required"))
	}
	return nil
}

type ScanProjectReq struct {
	ProjectIds []int64  `json:"projectIds"`
	ScanTypes  []string `json:"scanTypes"` //
}

func (vi *ScanProjectReq) Check() error {
	if len(vi.ProjectIds) == 0 {
		return portalI18.ProjectIDRequired(fmt.Errorf("project_id is required"))
	}
	if len(vi.ScanTypes) == 0 {
		return portalI18.ScanTypeRequired(fmt.Errorf("scan_type is required"))
	}
	return nil
}
