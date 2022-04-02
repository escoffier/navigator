package store

import (
	"context"
	"fmt"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type VulnDao struct {
	rdb *databases.RDBInstance
}

func NewVulnDao(rdb *databases.RDBInstance) *VulnDao {
	return &VulnDao{rdb: rdb}
}

func (v *VulnDao) List(ctx context.Context, query model.SqlBuilder, opts ...model.Option) ([]*model.Vuln, int64, error) {
	db := v.rdb.Get().WithContext(ctx)
	for _, f := range opts {
		db = f(db)
	}

	db = query.SqlBuild(db).Model(&model.Vuln{})

	var count int64
	if err := db.Count(&count).Error; err != nil {
		return nil, 0, err
	}
	var data = make([]*model.Vuln, 0, count)
	if err := db.Find(&data).Error; err != nil {
		return nil, 0, err
	}

	return data, count, nil
}

func (v *VulnDao) Detail(ctx context.Context, query model.SqlBuilder, opts ...model.Option) (*model.Vuln, error) {
	db := v.rdb.Get().WithContext(ctx)
	for _, f := range opts {
		db = f(db)
	}

	db = query.SqlBuild(db).Model(&model.Vuln{})

	var data model.Vuln
	if err := db.First(&data).Error; err != nil {
		return nil, err
	}

	return &data, nil
}

func (v *VulnDao) Count(ctx context.Context, opts ...model.Option) (*model.SeverityCount, error) {
	db := v.rdb.Get().WithContext(ctx)
	for _, f := range opts {
		db = f(db)
	}

	type severityCount struct {
		Severity string `gorm:"column:severity"`
		Count    int64  `gorm:"column:count"`
	}

	db = db.Model(&model.Vuln{}).Select("severity, count(*) as count").Group("severity")

	var datas []*severityCount
	if err := db.Find(&datas).Error; err != nil {
		return nil, err
	}

	var result model.SeverityCount
	for _, data := range datas {
		switch data.Severity {
		case model.SeverityCritical:
			result.Critical += data.Count
		case model.SeverityHigh:
			result.High += data.Count
		case model.SeverityMedium:
			result.Medium += data.Count
		case model.SeverityLow:
			result.Low += data.Count
		case model.SeverityUnknown:
			result.Unknown += data.Count
		}
	}

	return &result, nil
}

func (v *VulnDao) TopN(ctx context.Context, n int, opts ...model.Option) ([]*model.ImageListUnionScanImage, error) {
	db := v.rdb.Get().WithContext(ctx)
	for _, f := range opts {
		db = f(db)
	}

	var datas = make([]*model.ImageListUnionScanImage, 0, n)

	db = db.
		Model(&model.ScanImage{}).
		Joins(
			fmt.Sprintf("INNER JOIN %[1]s ON %[1]s.id = %[2]s.image_id",
				model.ImageList{}.TableName(),
				model.ScanImage{}.TableName(),
			),
		).
		Select(
			fmt.Sprintf(
				`%[1]s.severity_histogram_json severity_histogram_json, 
%[1]s.vuln_score vuln_score, 
%[2]s.full_repo_name full_repo_name, 
%[2]s.tags tags,
%[2]s.library library,
%[2]s.from_type from_type,
%[2]s.node_hostname node_hostname,
%[2]s.node_ip node_ip`,
				model.ScanImage{}.TableName(),
				model.ImageList{}.TableName(),
			),
		).
		Where(fmt.Sprintf("%s.status = ?", model.ScanImage{}.TableName()), model.ScanStatusSucceeded).
		Order(fmt.Sprintf("%s.vuln_score DESC", model.ScanImage{}.TableName())).
		Limit(n)

	if err := db.Find(&datas).Error; err != nil {
		return nil, err
	}

	return datas, nil
}
