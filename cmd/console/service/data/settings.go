package data

import (
	"context"
	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
)

func (s *Service) GetDataTTL(ctx context.Context, dataType string) (ttl int, err error) {
	var t def.GCTaskType
	err = t.ConvertFromStr(dataType)
	if err != nil {
		return 0, err
	}
	return s.ttlManager.GetTTLDayOffset(ctx, t)
}

func (s *Service) SetDataTTL(ctx context.Context, dataType string, ttl int) (err error) {
	var t def.GCTaskType
	err = t.ConvertFromStr(dataType)
	if err != nil {
		return err
	}
	return s.ttlManager.SetTTLDayOffset(ctx, t, ttl)
}

func (s *Service) GetDataWaterline(ctx context.Context) (percentage int, err error) {
	return s.waterlineManager.GetWaterline(ctx)
}

func (s *Service) SetDataWaterline(ctx context.Context, percentage int) error {
	return s.waterlineManager.SetWaterline(ctx, percentage)
}
