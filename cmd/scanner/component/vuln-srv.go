package component

import (
	"context"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type SearchVulnParam struct {
	PkgKeyword      string
	LanguageKeyword string
	TargetKeyword   string
	FrameKeyword    string
	VulnKeyword     string // 漏洞名搜索
	UniqueVuln      uint64
	Fields          []string
	ImageID         int64
	PkgName         string  // 软件包来源
	PkgVersion      string  // 软件包版本
	Sources         string  // 来源筛选,用逗号分隔
	CanFixed        string  // 是否可修复筛选
	SeverityInt     []int64 // 漏洞级别筛选
}

func GetVulnDefaultOmitFields() []string {
	return []string{"link_json", "metadata_json", "extra_info"}

}

type VulnServiceInterface interface {
	SearchVulns(ctx context.Context, param SearchVulnParam, filter *model.Filter) ([]model.Vuln, int64, error)
}

type VulnService struct {
	vuluDao *store.VulnDao
}

func (vn *VulnService) SearchVulns(ctx context.Context, param SearchVulnParam, filter *model.Filter) ([]model.Vuln, int64, error) {

	daoParam := store.SearchVulnParm{
		VulnKeyword:     param.VulnKeyword,
		PkgKeyword:      param.PkgKeyword,
		TargetKeyword:   param.TargetKeyword,
		LanguageKeyword: param.LanguageKeyword,
		FrameKeyword:    param.FrameKeyword,
		UniqueVuln:      param.UniqueVuln,
		Fields:          param.Fields,
		OmitFields:      GetVulnDefaultOmitFields(),
		ImageID:         param.ImageID,
		PkgName:         param.PkgName,
		PkgVersion:      param.PkgVersion,
		Sources:         nil,
		CanFixed:        param.CanFixed,
		SeverityInt:     param.SeverityInt,
		JustReturnCount: false,
	}

	if param.Sources != "" {
		daoParam.Sources = strings.Split(param.Sources, ",")
	}
	vulns, cnt, err := vn.vuluDao.SearchVuln(ctx, daoParam, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchImages.SearchVulns")
		return nil, 0, err
	}
	return vulns, cnt, nil
}

func NewVulnService(dal *store.VulnDao) *VulnService {
	return &VulnService{vuluDao: dal}
}
