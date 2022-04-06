package scap

import (
	"context"
	"errors"

	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/console/models/scap"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func (s *Service) RecordBatch(ctx context.Context, scapType uint8, limit, offset int64) ([]scap.RecordDetail, int64, error) {
	scapService, _ := scapper.GetService(ctx)
	var t string
	switch scapType {
	case 1:
		t = kube
	case 2:
		t = docker
	case 3:
		t = host
	}

	r, n, err := scapService.GetCheckHistory(ctx, offset, limit, "", t, "created_at", "desc")
	if err != nil {
		return nil, 0, err
	}

	var result = make([]scap.RecordDetail, 0, len(r))

	wg, nctx := errgroup.WithContext(ctx)

	for i := range r {
		result = append(result, scap.RecordDetail{
			CheckID:     r[i].CheckID,
			CheckType:   r[i].CheckType,
			ClusterID:   r[i].ClusterID,
			Operator:    r[i].Operator,
			ClusterName: r[i].ClusterName,
			CreatedAt:   r[i].CreatedAt,
			FinishedAt:  r[i].FinishedAt,
			PolicyID:    r[i].PolicyId,
			State:       r[i].State,
		})

		tmp := &(result[len(result)-1])
		// 获取策略名称
		wg.Go(func() error {
			var r model.ScapPolicy
			if err := s.rdb.Get().
				WithContext(nctx).
				Unscoped().
				Select("name").
				First(&r, tmp.PolicyID).
				Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}

			tmp.PolicyName = r.Name

			return nil
		})

	}
	if err := wg.Wait(); err != nil {
		logging.GetLogger().Err(err).Msg("查询策略名错误")
		return nil, 0, errors.New("获取列表失败")
	}

	return result, n, nil
}

func (s *Service) RecordDetail(ctx context.Context, recordId uint) error {
	panic("aaaa")
}
