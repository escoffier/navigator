package scap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/console/models/scap"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func (s *Service) RecordBatch(ctx context.Context, scapType string, limit, offset int) ([]scap.RecordDetail, int64, error) {
	scapService, _ := scapper.GetService(ctx)

	r, n, err := scapService.GetCheckHistory(ctx, offset, limit, "", scapType, "created_at", "desc")
	if err != nil {
		return nil, 0, err
	}

	var result = make([]scap.RecordDetail, 0, len(r))

	language := lang.Language(ctx)

	wg, nctx := errgroup.WithContext(ctx)
	for i := range r {
		result = append(result, scap.RecordDetail{
			CheckID:     r[i].TaskID,
			CheckType:   r[i].CheckType,
			ClusterID:   r[i].ClusterKey,
			Operator:    s.GetUserHelper(ctx, r[i].Operator),
			ClusterName: r[i].ClusterName,
			CreatedAt:   r[i].CreatedAt,
			FinishedAt:  r[i].FinishedAt,
			PolicyID:    r[i].PolicyID,
			State:       r[i].State,
		})

		tmp := &(result[len(result)-1])
		// 获取策略名称
		wg.Go(func() error {
			var r model.ScapPolicy
			if err := s.rdb.Get().WithContext(nctx).Unscoped().Select("name, is_default").
				First(&r, tmp.PolicyID).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}

			if r.IsDefault && language == lang.LanguageEN {
				r.Name = strings.ReplaceAll(r.Name, "合规检测默认策略", "default policy")
			}

			tmp.PolicyName = r.Name

			return nil
		})
	}

	if err = wg.Wait(); err != nil {
		logging.GetLogger().Err(err).Msg("查询策略名错误")
		return nil, 0, errors.New("获取列表失败")
	}

	return result, n, nil
}

func (s *Service) RecordDetail(ctx context.Context, checkUUID string) (*model.ScanHistory, error) {
	pgCtx, mpgCancel := context.WithTimeout(ctx, time.Second*2)
	defer mpgCancel()

	db := s.rdb.Get().WithContext(pgCtx).Model(&model.ScanHistory{})
	db = db.Where("task_id = ?", checkUUID)

	var scanHistory = make([]model.ScanHistory, 0)
	err := db.Find(&scanHistory).Error
	if err != nil {
		return nil, err
	}
	if len(scanHistory) == 0 {
		return nil, fmt.Errorf("not fond:%s", checkUUID)
	}

	value := scanHistory[0]
	return &value, nil

}
