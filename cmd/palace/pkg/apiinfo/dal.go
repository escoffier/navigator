package apiinfo

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func UpsertAPIInfo(ctx context.Context, rdb *databases.RDBInstance, api *model.TensorApi) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()
	return rdb.Get().WithContext(oneCtx).Model(&model.TensorApi{}).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "path"}, {Name: "method"}, {Name: "cluster"}, {Name: "namespace"}, {Name: "resource"}, {Name: "kind"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"pod_name",
			"ip",
			"port",
			"scheme",
			"content_type",
			"params",
		}),
	}).Create(api).Error

}

func GetClusterByName(ctx context.Context, rdb *gorm.DB, name string) (*model.TensorCluster, error) {
	cluster := model.TensorCluster{}
	err := rdb.WithContext(ctx).Where("name = ?", name).First(&cluster).Error
	return &cluster, err
}
