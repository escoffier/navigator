package data

import (
	"context"
	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"time"
)

func (s *Service) GetDataTTL(ctx context.Context, dataType string) (ttl int, err error) {
	tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var t def.GCTaskType
	err = t.ConvertFromStr(dataType)
	if err != nil {
		return 0, err
	}
	return s.ttlManager.GetTTLDayOffset(tctx, t)
}

func (s *Service) SetDataTTL(ctx context.Context, dataType string, ttl int) (err error) {
	tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var t def.GCTaskType
	err = t.ConvertFromStr(dataType)
	if err != nil {
		return err
	}
	return s.ttlManager.SetTTLDayOffset(tctx, t, ttl)
}

func (s *Service) GetDataWaterline(ctx context.Context) (percentage int, err error) {
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.waterlineManager.GetWaterline(tctx)
}

func (s *Service) SetDataWaterline(ctx context.Context, percentage int) error {
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.waterlineManager.SetWaterline(tctx, percentage)
}
