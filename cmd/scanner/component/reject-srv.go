package component

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type ImageRejectSrv interface {
	GetOverview(ctx context.Context, graph string) (*model.ImageRejectOverview, error)
	ListRejectRecord(ctx context.Context, search string, libraries []string, rejectReasons []int64, filter *model.Filter) ([]model.RejectRecord, int64, error)
	CreateImageWhitelist(ctx context.Context, name, library, tag, digest string) (*model.ImageWhitelist, error)
	ListImageWhitelist(ctx context.Context, search string, filter *model.Filter) ([]model.ImageWhitelist, int64, error)
	DeleteImageWhitelist(ctx context.Context, imageWhiteId int64) error

	DeletePolicy(ctx context.Context, id int64) error
	SearchRejectPolicy(ctx context.Context, library, globle string) ([]model.RejectPolicy, error)
	CreateSinglePolicy(ctx context.Context, policy model.RejectPolicy) error
	UpdateSinglePolicy(ctx context.Context, id int64, policy model.RejectPolicy) error
	CreateGlobalPolicy(ctx context.Context, policy model.GlobalRejectPolicy) error
}

type ImageReject struct {
	dbdal store.ScannerDalInterface
	// rejectDbDal store.BaseImageDalInterface
}

func (s *ImageReject) UpdateSinglePolicy(ctx context.Context, id int64, policy model.RejectPolicy) error {
	if err := checkRejectPolicy(policy); err != nil {
		return response.NewHttpError(http.StatusExpectationFailed, err)
	}
	if policy.Enable {
		// 一个仓库只能有一个生效策略，这里做一个限制
		policies, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.FalseString})
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("SearchRejectPolicy")
			return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
		}
		for i := range policies {
			if !policies[i].Enable {
				continue
			}
			for j := range policy.Library {
				for k := range policies[i].Library {
					if policy.Library[j] == policies[i].Library[k] && policies[i].ID != id {
						return response.NewHttpError(http.StatusExpectationFailed, fmt.Errorf("library:%s 已设置生效策略", policy.Library[j]))
					}
				}
			}
		}
	}
	if len(policy.Library) == 0 {
		return response.NewHttpError(http.StatusExpectationFailed, fmt.Errorf("请指定策略的仓库"))
	}
	updater := rejectPolicyToUpdater(policy)
	if err := s.dbdal.UpdatePolicy(ctx, store.SearchRejectPolicyParam{ID: id, Global: consts.FalseString, UpdateRejectVulns: true, RejectVulns: policy.RejectVulns}, updater); err != nil {
		logging.GetLogger().Error().Err(err).Msg("UpdateSinglePolicy")
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("更新策略失败"))
	}
	return nil
}

func (s *ImageReject) CreateGlobalPolicy(ctx context.Context, global model.GlobalRejectPolicy) error {
	policies, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.TrueString})
	if err != nil {
		return response.NewHttpError(http.StatusExpectationFailed, err)
	}
	if len(policies) == 0 {
		policy := model.RejectPolicy{
			CicdEnable:    global.CICDEnable,
			K8sEnable:     global.K8sEnable,
			Mode:          global.Mode,
			OnlineMonitor: global.OnlineMonitor,
			IsGlobal:      true,
		}

		policy.IsGlobal = true
		if _, err := s.dbdal.CreateRejectPolicy(ctx, policy); err != nil {
			logging.GetLogger().Error().Err(err).Msg("CreateGlobalPolicy")
			return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("创建策略失败"))
		}
	}

	// 全局策略对所有的策略都生效(但是gorm不允许更新整张表，所以这里分两次更新)
	updater := GlobalRejectPolicyToUpdater(global)

	if err := s.dbdal.UpdateGlobalPolicy(ctx, updater); err != nil {
		logging.GetLogger().Error().Err(err).Msg("CreateGlobalPolicy")
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("创建策略失败"))
	}

	return nil
}

func (s *ImageReject) SearchRejectPolicy(ctx context.Context, library, global string) ([]model.RejectPolicy, error) {
	policies, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{
		Library: library,
		Global:  global,
	})
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchRejectPolicy")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("查询策略失败"))
	}
	return policies, nil
}

func NewImageRejectSrc(dbdal store.ScannerDalInterface) *ImageReject {
	return &ImageReject{dbdal: dbdal}
}

func (s *ImageReject) DeletePolicy(ctx context.Context, id int64) error {
	if err := s.dbdal.DeletePolicy(ctx, id); err != nil {
		logging.GetLogger().Error().Err(err).Msg("DeletePolicy")
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("删除策略失败"))
	}
	return nil
}

func (s *ImageReject) GetOverview(ctx context.Context, graph string) (*model.ImageRejectOverview, error) {
	startAt := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), time.Now().Hour(), 0, 0, 0, time.UTC).Add(-23 * time.Hour)
	_, oneDayCount, err := s.dbdal.SearchRejectRecord(ctx, store.SearchRejectRecordParam{
		StartAt: startAt,
		EndAt:   time.Now().UTC(),
	}, model.EmptyFilterForTheTotalQuery())
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ImageReject.GetOverview.SearchRejectRecord")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	startAt = time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -6)
	_, sevenDayCount, err := s.dbdal.SearchRejectRecord(ctx, store.SearchRejectRecordParam{
		StartAt: startAt,
		EndAt:   time.Now().UTC(),
	}, model.EmptyFilterForTheTotalQuery())
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ImageReject.GetOverview.SearchRejectRecord")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	tops, err := s.dbdal.OverviewReasonTopN(ctx, store.OverviewReasonParam{TopN: 5}, nil)
	if err != nil {
		return nil, err
	}
	res := &model.ImageRejectOverview{
		OneDayCount:   oneDayCount,
		SevenDayCount: sevenDayCount,
		Graphs:        nil,
		RejectTop5:    tops,
	}

	var graphs []store.IntervalDateGroup
	graphsRes := make([]int64, 0)
	var inters []time.Time

	switch graph {
	case consts.TwentyFourHour:
		graphs, err = s.dbdal.OverviewForInterval(ctx, 24, consts.IntervalHour)
		inters = GenerationInterval(24, consts.IntervalHour)
	case consts.SevenDay:
		graphs, err = s.dbdal.OverviewForInterval(ctx, 7, consts.IntervalDay)
		inters = GenerationInterval(7, consts.IntervalDay)
	default:
		graphs = make([]store.IntervalDateGroup, 0)
	}

	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ImageReject.GetOverview.OverviewForInterval")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	j := 0
	for i := 0; i < len(inters); i++ {
		if j >= len(graphs) {
			// 把剩余的补上
			k := len(inters) - len(graphsRes)
			for m := 0; m < k; m++ {
				graphsRes = append(graphsRes, 0)
			}
			break // 讲道理不会出现j>=len(graphs)的情况,这里这样写只是为了让程序具有健壮性
		}
		if inters[i] == graphs[j].IntervalDateTime {
			graphsRes = append(graphsRes, graphs[j].Count)
			j++
		} else {
			graphsRes = append(graphsRes, 0)
		}
	}

	res.Graphs = graphsRes
	return res, nil
}

func (s *ImageReject) ListRejectRecord(ctx context.Context, search string, libraries []string, rejectReasons []int64,
	filter *model.Filter) ([]model.RejectRecord, int64, error) {
	records, cnt, err := s.dbdal.SearchRejectRecord(ctx, store.SearchRejectRecordParam{Libraries: libraries, RejectReasons: rejectReasons, Search: search}, filter)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ListRejectRecord")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	return records, cnt, nil
}

func (s *ImageReject) CreateImageWhitelist(ctx context.Context, name, library, tag, digest string) (*model.ImageWhitelist, error) {
	// library必须在我们的注册仓库，镜像可以不在我们的数据库中(7-19确定方案),K8s的阻断记录是没有digest的，
	rys, _, err := s.dbdal.SearchRegistry(ctx, store.SearchRegistryParam{LibraryUrl: library}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("CreateImageWhitelist")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("创建白名单出错"))
	}
	if len(rys) == 0 {
		return nil, response.NewHttpError(http.StatusBadRequest, fmt.Errorf(fmt.Sprintf("该仓库：%s 不是注册仓库，不能加白", library)))
	}
	// 这里验证一下参数
	if name == "" {
		return nil, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("no name"))
	}
	if library == "" {
		return nil, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("no library"))
	}
	if tag == "" {
		return nil, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("no tag"))
	}

	iw, err := s.dbdal.CreateImageWhitelist(ctx, model.ImageWhitelist{
		Library:      library,
		FullRepoName: name,
		Tag:          tag,
		Digest:       digest,
	})
	if err != nil {
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			// 如果是从k8s的阻断记录添加的白名单，这时是没有digest的，这里如果再加的话就要更新操作
			if digest != "" {
				whitelist, _, err := s.dbdal.SearchImageWhitelist(ctx, store.SearchImageWhitelistParam{Library: library, FullRepoName: name, Tag: tag}, nil)
				if err == nil && len(whitelist) > 0 && whitelist[0].Digest == "" {
					// 更新
					logging.GetLogger().WithContext(ctx).Infof("updating the digest of the whitelist")
					if err := s.dbdal.UpdateImageWhitelist(ctx,
						fmt.Sprintf("library = '%s' AND full_repo_name = '%s' AND tag = '%s'",
							library, name, tag), map[string]interface{}{"digest": digest}); err == nil {
						return iw, nil
					} else {
						logging.GetLogger().Error().Err(err).Msg("Error updating the digest of the whitelist")
						return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("更新白名单的Digest出错"))
					}
				}
			}
			return nil, response.NewHttpError(http.StatusBadRequest, errors.New("已存在，请不要重复添加"))
		}
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("创建白名单出错"))
	}
	return iw, nil
}

func (s *ImageReject) ListImageWhitelist(ctx context.Context, search string, filter *model.Filter) ([]model.ImageWhitelist, int64, error) {
	lists, cnt, err := s.dbdal.SearchImageWhitelist(ctx, store.SearchImageWhitelistParam{SearchWord: search}, filter)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ListImageWhitelist")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("查询镜像白名单出错"))
	}
	return lists, cnt, nil
}

func (s *ImageReject) DeleteImageWhitelist(ctx context.Context, imageWhiteId int64) error {
	err := s.dbdal.DeleteImageWhitelist(ctx, store.DeleteImageWhitelistParam{WhiteId: imageWhiteId})
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("DeleteImageWhitelist")
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("删除镜像白名单出错"))
	}
	return nil
}

func (s *ImageReject) CreateSinglePolicy(ctx context.Context, policy model.RejectPolicy) error {
	if err := checkRejectPolicy(policy); err != nil {
		return response.NewHttpError(http.StatusExpectationFailed, err)
	}

	for k := range policy.Library {
		if !strings.Contains(policy.Library[k], "http://") && !strings.Contains(policy.Library[k], "https://") {
			policy.Library[k] = "https://" + policy.Library[k]
		}
	}
	policy.IsGlobal = false
	// 一个仓库,可以建多个策略，但是只能有一个生效策略，这里做一个限制
	if policy.Enable {
		policies, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.FalseString})
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("SearchRejectPolicy")
			return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
		}
		for i := range policies {
			if !policies[i].Enable {
				continue
			}
			for j := range policy.Library {
				for k := range policies[i].Library {
					if policy.Library[j] == policies[i].Library[k] {
						return response.NewHttpError(http.StatusExpectationFailed, fmt.Errorf("library:%s 已设置生效策略", policy.Library[j]))
					}
				}
			}
		}
	}

	if _, err := s.dbdal.CreateRejectPolicy(ctx, policy); err != nil {
		logging.GetLogger().Error().Err(err).Msg("CreateSinglePolicy")
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	return nil
}

func GenerationInterval(interval int, intervalType string) []time.Time {
	res := make([]time.Time, 0)
	if interval < 1 {
		return res
	}
	now := time.Now().UTC()
	switch intervalType {
	case consts.IntervalHour:
		for i := interval - 1; i >= 0; i-- {
			endAt := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, time.UTC).Add(-time.Duration(i) * time.Hour).UTC()
			res = append(res, endAt)
		}
	case consts.IntervalDay:
		for i := interval - 1; i >= 0; i-- {
			endAt := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -i).UTC()
			res = append(res, endAt)
		}
	}
	return res
}
