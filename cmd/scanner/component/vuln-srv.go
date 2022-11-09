package component

import (
	"context"
	"encoding/json"
	"strings"
	"time"

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
	UniqueVulns     []uint64
	Fields          []string
	LayerDigest     string
	PkgName         string  // 软件包来源
	PkgVersion      string  // 软件包版本
	Sources         string  // 来源筛选,用逗号分隔
	CanFixed        string  // 是否可修复筛选
	SeverityInt     []int64 // 漏洞级别筛选
	ImageIds        []int64 // 镜像ID
}

type SearchScanLayerParam struct {
	ImageID      int64
	LayerDigests []string
}

func GetVulnDefaultOmitFields() []string {
	return []string{"link_json", "metadata_json", "extra_info"}
}

type VulnServiceInterface interface {
	SearchVulns(ctx context.Context, param SearchVulnParam, filter *model.Filter) ([]*model.Vuln, int64, error)
	SearchLayerVuln(ctx context.Context, param SearchScanLayerParam, filter *model.Filter) ([]*model.ScanLayer, int64, error)
	SetImageRiskToRedis(ctx context.Context, data model.ImageRiskOverRedis) error
}

type VulnService struct {
	vuluDal store.VulnDalInterface
	scanDal store.ScannerDalInterface
}

func (vn *VulnService) SearchVulns(ctx context.Context, param SearchVulnParam, filter *model.Filter) ([]*model.Vuln, int64, error) {
	daoParam := store.SearchVulnParam{
		VulnKeyword:     param.VulnKeyword,
		PkgKeyword:      param.PkgKeyword,
		TargetKeyword:   param.TargetKeyword,
		LanguageKeyword: param.LanguageKeyword,
		FrameKeyword:    param.FrameKeyword,
		UniqueVulns:     param.UniqueVulns,
		Fields:          param.Fields,
		ImageIds:        param.ImageIds,
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
	vulns, cnt, err := vn.vuluDal.SearchVuln(ctx, daoParam, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchImages.SearchVulns")
		return nil, 0, err
	}
	return vulns, cnt, nil
}

func (vn *VulnService) SetImageRiskToRedis(ctx context.Context, data model.ImageRiskOverRedis) error {
	byts, err := json.Marshal(data.Data)
	if err != nil {
		return err
	}

	redis, err := store.GetRedisClient(0)
	if err != nil {
		logging.GetLogger().Err(err).Msg("Redis 0 can't get")
		return err
	}
	err = redis.Set(ctx, data.Key, byts, time.Hour*144).Err()
	if err != nil {
		logging.GetLogger().Err(err).Msgf("Updata risk cache error image:%v", data.Key)
		return err
	}
	return nil
}

func NewVulnService(vulnDal store.VulnDalInterface, scanDal store.ScannerDalInterface) *VulnService {
	return &VulnService{vuluDal: vulnDal, scanDal: scanDal}
}

func (vn *VulnService) SearchLayerVuln(ctx context.Context, param SearchScanLayerParam, filter *model.Filter) ([]*model.ScanLayer, int64, error) {
	layers, cnt, err := vn.scanDal.SearchScanLayer(ctx, store.SearchScanLayerParam{
		ImageId:      param.ImageID,
		LayerDigests: param.LayerDigests,
	}, filter)

	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchImages.SearchLayerVuln")
		return nil, 0, err
	}
	return layers, cnt, nil
}
