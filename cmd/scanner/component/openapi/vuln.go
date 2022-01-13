package openapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

type VulnService struct {
	dao *store.VulnDao
}

func NewVulnService(psql *rdbtools.GormWrapper) *VulnService {
	return &VulnService{
		dao: store.NewVulnDao(psql),
	}
}

func (v *VulnService) List(ctx context.Context, req model.SqlBuilder) ([]*model.Vuln, int64, error) {
	datas, count, err := v.dao.List(
		ctx,
		req,
		func(db *gorm.DB) *gorm.DB {
			return db.Omit("extra_info")
		},
	)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, 0, nil
		}
		logging.Get().Err(err).Msgf("获取漏洞列表失败失败, req: %+v", req)
		return nil, 0, errors.New("get vulns faield")
	}

	for _, data := range datas {
		_ = json.Unmarshal(data.MetadataJSON, &data.Metadata)
		_ = json.Unmarshal(data.LinkJSON, &data.Link)
	}

	return datas, count, nil
}

func (v *VulnService) Detail(ctx context.Context, req model.SqlBuilder) (*model.Vuln, error) {
	data, err := v.dao.Detail(
		ctx,
		req,
		func(db *gorm.DB) *gorm.DB {
			return db.Omit("extra_info")
		},
	)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		logging.Get().Err(err).Msgf("获取漏洞详情失败, req: %+v", req)
		return nil, errors.New("get vuln detail faield")
	}

	_ = json.Unmarshal(data.MetadataJSON, &data.Metadata)
	_ = json.Unmarshal(data.LinkJSON, &data.Link)

	return data, nil
}

func (v *VulnService) CountBySeverity(ctx context.Context) (*model.SeverityCount, error) {
	data, err := v.dao.Count(ctx)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		logging.Get().Err(err).Msgf("获取漏洞统计信息失败")
		return nil, errors.New("get vuln' statistic faield")
	}

	return data, nil
}

func (v *VulnService) CountTopN(ctx context.Context, n int) ([]*model.ImageListUnionScanImage, error) {
	datas, err := v.dao.TopN(ctx, n)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		logging.Get().Err(err).Msgf("获取漏洞Top%d信息失败", n)
		return nil, fmt.Errorf("get vuln' top%d faield", n)
	}

	for _, v := range datas {
		if len(v.SeverityHistogramJSON) != 0 {
			_ = json.Unmarshal(v.SeverityHistogramJSON, &v.SeverityHistogram)
		}
	}

	return datas, nil
}
