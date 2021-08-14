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
	DeletePolicy(ctx context.Context, id int64)
}

type ImageReject struct {
	dbdal store.ScannerDalInterface
}

func NewImageRejectSrc(dbdal store.ScannerDalInterface) *ImageReject {
	return &ImageReject{dbdal: dbdal}
}

func (s *ImageReject) DeletePolicy(ctx context.Context, id int64) {
	s.dbdal.DeletePolicy(ctx, id)
}

func (s *ImageReject) GetOverview(ctx context.Context, graph string) (*model.ImageRejectOverview, error) {
	startAt := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), time.Now().Hour(), 0, 0, 0, time.UTC).Add(-23 * time.Hour)
	_, oneDayCount, err := s.dbdal.SearchRejectRecord(ctx, store.SearchRejectRecordParam{
		StartAt: startAt,
		EndAt:   time.Now().UTC(),
	}, model.EmptyFilterForTheTotalQuery())
	if err != nil {
		return nil, err
	}

	startAt = time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -6)
	_, sevenDayCount, err := s.dbdal.SearchRejectRecord(ctx, store.SearchRejectRecordParam{
		StartAt: startAt,
		EndAt:   time.Now().UTC(),
	}, model.EmptyFilterForTheTotalQuery())
	if err != nil {
		return nil, err
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
		logging.GetLogger().WithContext(ctx).Errorf(err, "GetOverview statistics:%s error", graph)
		return res, nil
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
		return nil, 0, response.NewHttpError(http.StatusBadRequest, err)
	}
	return records, cnt, nil
}

func (s *ImageReject) CreateImageWhitelist(ctx context.Context, name, library, tag, digest string) (*model.ImageWhitelist, error) {
	// library必须在我们的注册仓库，镜像可以不在我们的数据库中(7-19确定方案),K8s的阻断记录是没有digest的，
	rys, _, err := s.dbdal.SearchRegistry(ctx, store.SearchRegistryParam{LibraryUrl: library}, nil)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "CreateImageWhitelist search  library error")
		return nil, response.NewHttpError(http.StatusBadRequest, fmt.Errorf(fmt.Sprintf("查询仓库：%s 出错：%s", library, err.Error())))
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
						logging.GetLogger().WithContext(ctx).Errorf(err, "Error updating the digest of the whitelist")
						return nil, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("更新白名单的Digest出错"))
					}
				}
			}
			return nil, response.NewHttpError(http.StatusBadRequest, errors.New("已存在，请不要重复添加"))
		}
		return nil, response.NewHttpError(http.StatusBadRequest, fmt.Errorf(fmt.Sprintf("创建出错：%s", err.Error())))
	}
	return iw, nil
}

func (s *ImageReject) ListImageWhitelist(ctx context.Context, search string, filter *model.Filter) ([]model.ImageWhitelist, int64, error) {
	lists, cnt, err := s.dbdal.SearchImageWhitelist(ctx, store.SearchImageWhitelistParam{SearchWord: search}, filter)
	if err != nil {
		return nil, 0, response.NewHttpError(http.StatusBadRequest, fmt.Errorf(fmt.Sprintf("查询镜像白名单出错：%s", err.Error())))
	}
	return lists, cnt, nil
}

func (s *ImageReject) DeleteImageWhitelist(ctx context.Context, imageWhiteId int64) error {
	err := s.dbdal.DeleteImageWhitelist(ctx, store.DeleteImageWhitelistParam{WhiteId: imageWhiteId})
	if err != nil {
		return response.NewHttpError(http.StatusBadRequest, fmt.Errorf(fmt.Sprintf("删除镜像白名单出错：镜像ID：%d,error: %s", imageWhiteId, err.Error())))
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
