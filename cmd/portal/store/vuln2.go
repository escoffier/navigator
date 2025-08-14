package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"
)

type SourceCheckScanDao struct {
	db *databases.RDBInstance
}

func NewSourceCheckScanDao(db *databases.RDBInstance) *SourceCheckScanDao {
	return &SourceCheckScanDao{db: db}
}

type SourceCheckScanDal interface {
	CreateVuln(ctx context.Context, projectID string, vulns []*model.SourceCheckVuln) error
	SearchVuln(ctx context.Context, param model.SearchVulnParam) ([]*model.SourceCheckVuln, int64, error)
	DeleteVuln(ctx context.Context, projectUuid string) error
	CreateLicense(ctx context.Context, projectUuid string, licenses []*model.SourceCheckLicense) error
	SearchLicense(ctx context.Context, param model.SearchVulnParam) ([]*model.SourceCheckLicense, int64, error)
	DeleteLicense(ctx context.Context, projectUuid string) error
	CreateComponent(ctx context.Context, projectUuid string, components []*model.SourceCheckComponent) error
	SearchComponent(ctx context.Context, param model.SearchVulnParam) ([]*model.SourceCheckComponent, int64, error)
	DeleteComponent(ctx context.Context, projectUuid string) error

	CreateSummary(ctx context.Context, scanResult *model.SourceCheckSummary) error
	GetSummary(ctx context.Context, param model.SearchScanResultParam) (*model.SourceCheckSummary, error)
	DeleteSummary(ctx context.Context, projectUuid string) error
}

func (s *SourceCheckScanDao) CreateVuln(ctx context.Context, projectUuid string, vulns []*model.SourceCheckVuln) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 10000*time.Second)
	defer cancel()
	for i := range vulns {
		vulns[i].ProjectUuid = projectUuid
		vulns[i].Serialize()
	}

	// 先删除该应用的旧漏洞记录
	if err := s.DeleteVuln(timeoutCtx, projectUuid); err != nil {
		return fmt.Errorf("delete old vulns failed: %w", err)
	}

	for i := range vulns {
		vu := vulns[i]
		err := s.db.Get().WithContext(timeoutCtx).Create(vu).Error
		if err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			}
			return err
		}
	}
	return nil
}

func (s *SourceCheckScanDao) SearchVuln(ctx context.Context, param model.SearchVulnParam) ([]*model.SourceCheckVuln, int64, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	db := s.db.Get().WithContext(timeoutCtx).Where("deleted_at = 0")

	if param.ProjectUuid != "" {
		db = db.Where("project_uuid = ?", param.ProjectUuid)
	}
	if param.SourceCheckUuid != "" {
		db = db.Where("source_check_uuid = ?", param.SourceCheckUuid)
	}
	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
	}
	if len(param.UniqueIds) > 0 {
		db = db.Where("unique_id IN ? ", param.UniqueIds)
	}

	// 获取总数
	var total int64
	if err := db.Model(&model.SourceCheckVuln{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count vulns failed: %w", err)
	}
	db = imagesec.AddFilter(db, param.Filter)

	// 分页查询
	var vulns []*model.SourceCheckVuln
	if err := db.Find(&vulns).Error; err != nil {
		return nil, 0, fmt.Errorf("find vulns failed: %w", err)
	}

	// 反序列化查询结果
	for i := range vulns {
		vulns[i].Deserialize()
	}

	return vulns, total, nil
}

func (s *SourceCheckScanDao) DeleteVuln(ctx context.Context, projectUuid string) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	db := s.db.Get().WithContext(timeoutCtx).Where("project_uuid = ?", projectUuid)
	if err := db.Delete(&model.SourceCheckVuln{}).Error; err != nil {
		return fmt.Errorf("delete vulns failed: %w", err)
	}
	return nil
}

func (s *SourceCheckScanDao) CreateLicense(ctx context.Context, projectUuid string, licenses []*model.SourceCheckLicense) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 10000*time.Second)
	defer cancel()
	for i := range licenses {
		licenses[i].ProjectUuid = projectUuid
		licenses[i].Serialize()
	}

	// 先删除该应用的旧许可记录
	if err := s.DeleteLicense(timeoutCtx, projectUuid); err != nil {
		return fmt.Errorf("delete old licenses failed: %w", err)
	}

	for i := range licenses {
		vu := licenses[i]
		err := s.db.Get().WithContext(timeoutCtx).Create(vu).Error
		if err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			}
			return err
		}
	}

	return nil
}

func (s *SourceCheckScanDao) SearchLicense(ctx context.Context, param model.SearchVulnParam) ([]*model.SourceCheckLicense, int64, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	db := s.db.Get().WithContext(timeoutCtx)

	// 根据应用ID过滤
	if param.ProjectUuid != "" {
		db = db.Where("project_uuid = ?", param.ProjectUuid)
	}
	if param.SourceCheckUuid != "" {
		db = db.Where("source_check_uuid = ?", param.SourceCheckUuid)
	}
	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
	}

	// 根据UniqueIds过滤
	if len(param.UniqueIds) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueIds)
	}

	// 获取总数
	var total int64
	if err := db.Model(&model.SourceCheckLicense{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count licenses failed: %w", err)
	}
	db = imagesec.AddFilter(db, param.Filter)

	// 分页查询
	var licenses []*model.SourceCheckLicense
	if err := db.Find(&licenses).Error; err != nil {
		return nil, 0, fmt.Errorf("find licenses failed: %w", err)
	}

	// 反序列化查询结果
	for i := range licenses {
		licenses[i].Deserialize()
	}

	return licenses, total, nil
}

func (s *SourceCheckScanDao) DeleteLicense(ctx context.Context, projectUuid string) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	db := s.db.Get().WithContext(timeoutCtx).Where("project_uuid = ?", projectUuid)
	if err := db.Delete(&model.SourceCheckLicense{}).Error; err != nil {
		return fmt.Errorf("delete licenses failed: %w", err)
	}
	return nil
}

func (s *SourceCheckScanDao) CreateComponent(ctx context.Context, projectUuid string, components []*model.SourceCheckComponent) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for i := range components {
		components[i].ProjectUuid = projectUuid
		components[i].Serialize()
	}

	// 先删除该应用的旧组件记录
	if err := s.DeleteComponent(timeoutCtx, projectUuid); err != nil {
		return fmt.Errorf("delete old components failed: %w", err)
	}

	for i := range components {
		vu := components[i]
		err := s.db.Get().WithContext(timeoutCtx).Create(vu).Error
		if err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			}
			return err
		}
	}

	return nil
}

func (s *SourceCheckScanDao) SearchComponent(ctx context.Context, param model.SearchVulnParam) ([]*model.SourceCheckComponent, int64, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	db := s.db.Get().WithContext(timeoutCtx).Model(&model.SourceCheckComponent{})

	// 根据应用ID过滤
	if param.ProjectUuid != "" {
		// 这里假设ProjectUuid对应project_uuid，根据实际业务逻辑调整
		db = db.Where("project_uuid = ?", param.ProjectUuid)
	}
	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
	}
	// 根据UniqueIds过滤
	if len(param.UniqueIds) > 0 {
		db = db.Where("id IN ?", param.UniqueIds)
	}
	if param.SourceCheckUuid != "" {
		// 这里假设SourceCheckUuid对应source_check_uuid，根据实际业务逻辑调整
		db = db.Where("source_check_uuid = ?", param.SourceCheckUuid)
	}

	// 获取总数
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count components failed: %w", err)
	}

	db = imagesec.AddFilter(db, param.Filter)

	// 分页查询
	var components []*model.SourceCheckComponent
	if err := db.Find(&components).Error; err != nil {
		return nil, 0, fmt.Errorf("find components failed: %w", err)
	}

	// 反序列化查询结果
	for i := range components {
		components[i].Deserialize()
	}

	return components, total, nil
}

func (s *SourceCheckScanDao) DeleteComponent(ctx context.Context, projectUuid string) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	db := s.db.Get().WithContext(timeoutCtx).Where("project_uuid = ?", projectUuid)
	if err := db.Delete(&model.SourceCheckComponent{}).Error; err != nil {
		return fmt.Errorf("delete components failed: %w", err)
	}
	return nil
}

// CreateSummary 创建SourceCheck扫描摘要
func (s *SourceCheckScanDao) CreateSummary(ctx context.Context, scanResult *model.SourceCheckSummary) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	if err := scanResult.Check(); err != nil {
		return err
	}

	scanResult.Serialize()

	// 先删除旧的摘要记录
	if err := s.DeleteSummary(timeoutCtx, scanResult.ProjectUuid); err != nil {
		return fmt.Errorf("delete old summary failed: %w", err)
	}

	// 创建新的摘要记录
	if err := s.db.Get().WithContext(timeoutCtx).Create(scanResult).Error; err != nil {
		return fmt.Errorf("create summary failed: %w", err)
	}

	return nil
}

// GetSummary 获取SourceCheck扫描摘要
func (s *SourceCheckScanDao) GetSummary(ctx context.Context, param model.SearchScanResultParam) (*model.SourceCheckSummary, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := param.Check(); err != nil {
		return nil, err
	}

	var summary model.SourceCheckSummary

	db := s.db.Get().WithContext(timeoutCtx).Model(&model.SourceCheckSummary{})
	if param.SourceCheckUuid != "" {
		db = db.Where("source_check_uuid = ?", param.SourceCheckUuid)
	}
	if param.ProjectUuid != "" {
		db = db.Where("project_uuid = ?", param.ProjectUuid)
	}

	if err := db.First(&summary).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("summary not found for project: %s", param.ProjectUuid)
		}
		return nil, fmt.Errorf("get summary failed: %w", err)
	}

	summary.Deserialize()
	return &summary, nil
}

// DeleteSummary 删除SourceCheck扫描摘要
func (s *SourceCheckScanDao) DeleteSummary(ctx context.Context, projectUuid string) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	db := s.db.Get().WithContext(timeoutCtx).Where("project_uuid = ?", projectUuid)
	if err := db.Delete(&model.SourceCheckSummary{}).Error; err != nil {
		return fmt.Errorf("delete summary failed: %w", err)
	}
	return nil
}
