package store

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	scannerCi "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
	"gitlab.com/security-rd/go-pkg/databases"
)

type CiScanDal interface {
	SearchCiScan(ctx context.Context, param SearchCiScanParam) ([]*scannerCi.CiScan, int64, error)
	SearchCiVuln(ctx context.Context, param SearchCiVulnParam) ([]*scannerCi.CiVulns, int64, error)
	GetWhitelist(ctx context.Context) ([]scannerCi.CiWhitelist, error)
}

type CiScanDao struct {
	db *databases.RDBInstance
}

func NewCiScanDao(db *databases.RDBInstance) *CiScanDao {
	return &CiScanDao{db: db}
}

// SearchCiScanParam CI扫描查询参数
type SearchCiScanParam struct {
	ProjectUuid string           `json:"projectUuid"` // Portal项目UUID
	StartID     int64            `json:"startID"`     // 分页起始ID
	Filter      *imagesec.Filter `json:"filter"`      // 分页和排序
}

// SearchCiVulnParam CI漏洞查询参数
type SearchCiVulnParam struct {
	ProjectUuid string           `json:"projectUuid"` // Portal项目UUID
	StartID     int64            `json:"startID"`     // 分页起始ID
	Filter      *imagesec.Filter `json:"filter"`      // 分页和排序
}

func (p *SearchCiScanParam) Check() error {
	if p.ProjectUuid == "" {
		return fmt.Errorf("project_uuid is required")
	}
	return nil
}

func (p *SearchCiVulnParam) Check() error {
	if p.ProjectUuid == "" {
		return fmt.Errorf("project_uuid is required")
	}
	return nil
}

// SearchCiScan 查询CI扫描记录
func (s *CiScanDao) SearchCiScan(ctx context.Context, param SearchCiScanParam) ([]*scannerCi.CiScan, int64, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := param.Check(); err != nil {
		return nil, 0, err
	}

	res := make([]*scannerCi.CiScan, 0)
	db := s.db.Get().WithContext(timeoutCtx).Model(new(scannerCi.CiScan))

	if param.ProjectUuid != "" {
		db = db.Where("project_uuid = ?", param.ProjectUuid)
	}
	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
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
	for i := range res {
		res[i].Deserialize()
	}

	return res, cnt, nil
}

// SearchCiVuln 查询CI漏洞记录
func (s *CiScanDao) SearchCiVuln(ctx context.Context, param SearchCiVulnParam) ([]*scannerCi.CiVulns, int64, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := param.Check(); err != nil {
		return nil, 0, err
	}

	res := make([]*scannerCi.CiVulns, 0)

	// 首先通过project_uuid查找对应的CiScan记录，获取image_id列表
	var ciScans []*scannerCi.CiScan
	scanDb := s.db.Get().WithContext(timeoutCtx).Model(new(scannerCi.CiScan))
	if param.ProjectUuid != "" {
		scanDb = scanDb.Where("project_uuid = ?", param.ProjectUuid)
	}
	if param.StartID > 0 {
		scanDb = scanDb.Where("id > ?", param.StartID)
	}
	if err := scanDb.Find(&ciScans).Error; err != nil {
		return nil, 0, err
	}

	if len(ciScans) == 0 {
		return res, 0, nil
	}

	// 提取image_id列表
	imageIds := make([]int64, len(ciScans))
	for i, scan := range ciScans {
		imageIds[i] = scan.ID
	}

	// 通过CiVulnImage表关联查询漏洞
	vulnImageDb := s.db.Get().WithContext(timeoutCtx).Table("ivan_ci_scan_vuln_images").
		Where("image_id IN ?", imageIds)

	var vulnImages []scannerCi.CiVulnImage
	if err := vulnImageDb.Find(&vulnImages).Error; err != nil {
		return nil, 0, err
	}

	if len(vulnImages) == 0 {
		return res, 0, nil
	}

	// 提取unique_vuln列表
	uniqueVulns := make([]uint64, len(vulnImages))
	for i, vi := range vulnImages {
		uniqueVulns[i] = vi.UniqueVuln
	}

	// 查询漏洞详情
	db := s.db.Get().WithContext(timeoutCtx).Model(new(scannerCi.CiVulns))
	db = db.Where("unique_vuln IN ?", uniqueVulns)

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

func (c *CiScanDao) GetWhitelist(ctx context.Context) ([]scannerCi.CiWhitelist, error) {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	var res []scannerCi.CiWhitelist
	db := c.db.Get().Model(&scannerCi.CiWhitelist{}).WithContext(ctxd).Order("updated_at DESC")

	err := db.Find(&res).Error
	if err != nil {
		return []scannerCi.CiWhitelist{}, err
	}
	return res, nil
}
