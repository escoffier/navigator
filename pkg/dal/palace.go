package dal

import (
	"context"
	"strconv"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	onDupUpdatedColsForAGEvent = []string{
		"severity",
		"nodes_num",
		"events_num",
		"updated_at",
	}
)

func UpsertAssociatedGraphEvent(ctx context.Context, rdb *gorm.DB, e *model.PalaceAssociatedGraphEvent) (int64, error) {
	tctx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
	defer cancel()
	err := util.RetryWithBackoff(tctx, func() error {
		oneCtx, cancel := context.WithTimeout(tctx, 500*time.Millisecond)
		defer cancel()
		return rdb.WithContext(oneCtx).Model(e).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForAGEvent),
		}).Create(e).Error
	})
	if err != nil {
		return 0, err
	}
	return e.ID, nil
}

func CreateSignalAssociation(ctx context.Context, rdb *gorm.DB, a *model.PalaceEventSignalAssociation) (uint32, error) {
	tctx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()

	a.UUID = util.GenerateUUID(strconv.FormatInt(a.AggrEvtID, 10), a.AggrKey, a.SignalID)
	err := rdb.WithContext(tctx).Model(a).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "uuid"}},
		DoNothing: true,
	}).Create(a).Error
	if err != nil {
		return 0, err
	}
	return a.UUID, nil
}

func CreateAssociationLinks(ctx context.Context, rdb *gorm.DB, l *model.PalaceAssociationLink) (uint32, error) {
	tctx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()

	l.UUID = util.GenerateUUID(
		strconv.FormatInt(l.AggrEvtID, 10),
		l.SrcClusterKey,
		l.SrcLocType,
		l.SrcLocExpr,
		l.DestClusterKey,
		l.DestLocType,
		l.DestLocExpr,
	)
	err := rdb.WithContext(tctx).Model(l).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "uuid"}},
		DoNothing: true,
	}).Create(l).Error
	if err != nil {
		return 0, err
	}
	return l.UUID, nil
}
