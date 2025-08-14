package store

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/portalI18"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/security-rd/go-pkg/databases"
)

type CodesecScanDal interface {
	CreateVuln(ctx context.Context, projectUuid string, vulns []*model.CodeSecVuln) error
	SearchVuln(ctx context.Context, param model.SearchVulnParam) ([]*model.CodeSecVuln, int64, error)
	DeleteVuln(ctx context.Context, projectUuid string) error

	CreateSummary(ctx context.Context, scanResult *model.CodesecSummary) error
	GetSummary(ctx context.Context, param model.SearchScanResultParam) (*model.CodesecSummary, error)
	DeleteSummary(ctx context.Context, projectUuid string) error
}

type CodesecScanDao struct {
	db *databases.RDBInstance
}

func NewCodesecScanDao(db *databases.RDBInstance) *CodesecScanDao {
	return &CodesecScanDao{db: db}
}

func (s *CodesecScanDao) CreateVuln(ctx context.Context, projectUuid string, vulns []*model.CodeSecVuln) error {
	if len(vulns) == 0 {
		return nil
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 3000*time.Second)
	defer cancel()

	// 先删除该项目下的所有漏洞数据
	if err := s.DeleteVuln(timeoutCtx, projectUuid); err != nil {
		return fmt.Errorf("failed to delete existing vulns: %v", err)
	}

	// 批量插入新数据
	for i := range vulns {
		vu := vulns[i]
		vu.ProjectUuid = projectUuid
		vu.Serialize()
		if err := s.db.Get().WithContext(timeoutCtx).Create(vu).Error; err != nil {
			return fmt.Errorf("failed to create vuln: %v", err)
		}
	}
	return nil
}

// SearchVuln 查询漏洞记录
func (s *CodesecScanDao) SearchVuln(ctx context.Context, param model.SearchVulnParam) ([]*model.CodeSecVuln, int64, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := param.Check(); err != nil {
		return nil, 0, err
	}

	res := make([]*model.CodeSecVuln, 0)
	db := s.db.Get().WithContext(timeoutCtx).Model(new(model.CodeSecVuln))

	if param.ProjectUuid != "" {
		db = db.Where("project_uuid = ?", param.ProjectUuid)
	}
	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
	}
	if param.CodesecUuid != "" {
		db = db.Where("codesec_app_id = ?", param.CodesecUuid)
	}
	// 获取总数
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}

	// 应用分页和排序
	db = imagesec.AddFilter(db, param.Filter)

	// 执行查询
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}

	// 反序列化查询结果
	for i := range res {
		res[i].Deserialize()
	}

	return res, cnt, nil
}

func (s *CodesecScanDao) DeleteVuln(ctx context.Context, projectUuid string) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	db := s.db.Get().WithContext(timeoutCtx).Where("project_uuid = ?", projectUuid)
	if err := db.Delete(&model.CodeSecVuln{}).Error; err != nil {
		return err
	}
	return nil
}

func (s *CodesecScanDao) CreateSummary(ctx context.Context, scanResult *model.CodesecSummary) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	scanResult.Serialize()

	if err := scanResult.Check(); err != nil {
		return err
	}

	// 先删除该项目下的扫描结果
	if err := s.DeleteSummary(timeoutCtx, scanResult.ProjectUuid); err != nil {
		return fmt.Errorf("failed to delete existing scan result: %v", err)
	}

	if err := s.db.Get().WithContext(timeoutCtx).Create(scanResult).Error; err != nil {
		return fmt.Errorf("failed to create scan result: %v", err)
	}
	return nil
}

func (s *CodesecScanDao) GetSummary(ctx context.Context, param model.SearchScanResultParam) (*model.CodesecSummary, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := param.Check(); err != nil {
		return nil, err
	}

	res := make([]*model.CodesecSummary, 0)
	db := s.db.Get().WithContext(timeoutCtx).Model(new(model.CodesecSummary))

	if param.ProjectUuid != "" {
		db = db.Where("project_uuid = ?", param.ProjectUuid)
	}
	if param.CodesecUuid != "" {
		db = db.Where("codesec_app_id = ?", param.CodesecUuid)
	}
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, portalI18.ScanResultNotExist(fmt.Errorf("scan result not found"))
	}

	// 反序列化查询结果
	res[0].Deserialize()
	return res[0], nil
}

func (s *CodesecScanDao) DeleteSummary(ctx context.Context, projectUuid string) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	db := s.db.Get().WithContext(timeoutCtx).Where("project_uuid = ?", projectUuid)
	if err := db.Delete(&model.CodesecSummary{}).Error; err != nil {
		return err
	}
	return nil
}
