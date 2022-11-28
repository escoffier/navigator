package dal

import (
	"context"
	"time"

	"gitlab.com/security-rd/go-pkg/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func UpsertNetworkFlow(ctx context.Context, db *gorm.DB, flow *model.TensorNetworkFlow) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer oneCancel()

	return db.WithContext(oneCtx).Model(&model.TensorNetworkFlow{}).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "uuid"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"updated_at",
			"status",
		}),
	}).Create(flow).Error
}
