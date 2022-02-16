package dal

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	onDupUpdatedColsForBait = []string{
		"name",
	}
)

type BaitsQueryOption struct {
	whereEqCondition map[string]interface{}
	whereInCondition map[string]interface{}
	columnQuery      colQuery
	multicolumnQuery map[string]string
	baitIds          []uint32
}

func BaitsQuery() *BaitsQueryOption {
	return &BaitsQueryOption{
		whereEqCondition: make(map[string]interface{}, 3),
		whereInCondition: make(map[string]interface{}, 2),
		multicolumnQuery: make(map[string]string),
	}
}

func (q *BaitsQueryOption) WithCluster(clusterKey string) *BaitsQueryOption {
	q.whereEqCondition["cluster_key"] = clusterKey
	return q
}

func (q *BaitsQueryOption) WithNamespace(ns string) *BaitsQueryOption {
	q.whereEqCondition["namespace"] = ns
	return q
}

func (q *BaitsQueryOption) WithName(ns string) *BaitsQueryOption {
	q.whereEqCondition["name"] = ns
	return q
}

func (q *BaitsQueryOption) WithId(id uint32) *BaitsQueryOption {
	q.whereEqCondition["id"] = id
	return q
}

func (q *BaitsQueryOption) WithBaitId(id uint32) *BaitsQueryOption {
	q.whereEqCondition["bait_id"] = id
	return q
}

func (q *BaitsQueryOption) WithWorkloadStatus(status string) *BaitsQueryOption {
	q.whereEqCondition["workload_status"] = status
	return q
}

func (q *BaitsQueryOption) WithAlerts(haveAlerts bool) *BaitsQueryOption {
	q.whereEqCondition["have_alerts"] = haveAlerts
	return q
}

func (q *BaitsQueryOption) WithColumnQuery(column, query string) *BaitsQueryOption {
	q.columnQuery.column = column
	q.columnQuery.query = query
	return q
}

func (q *BaitsQueryOption) WithMultiColumnQuery(column string, query string) *BaitsQueryOption {
	q.multicolumnQuery[column] = query
	return q
}

func (q *BaitsQueryOption) WithInConditionCustom(column string, value interface{}) *BaitsQueryOption {
	q.whereInCondition[column] = value
	return q
}

func (q *BaitsQueryOption) WithBaitIds(ids []uint32) *BaitsQueryOption {
	q.baitIds = append(q.baitIds, ids...)
	return q
}

func (q *BaitsQueryOption) GetClusterOption() (string, bool) {
	v, ok := q.whereEqCondition["cluster_key"]
	return v.(string), ok
}

func (q *BaitsQueryOption) GetNamespace() (string, bool) {
	v, ok := q.whereEqCondition["namespace"]
	return v.(string), ok
}

func (q *BaitsQueryOption) GetName() (string, bool) {
	v, ok := q.whereEqCondition["name"]
	return v.(string), ok
}

type BaitImagesQueryOption struct {
	whereEqCondition map[string]interface{}
	whereInCondition map[string]interface{}
	columnQuery      colQuery
}

func GetBaitImages(ctx context.Context, rdb *gorm.DB, offset, limit int) ([]*model.BaitImages, error) {
	dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var baitImages []*model.BaitImages
	notFound := false
	err := util.RetryWithBackoff(dbCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
		defer cancel()

		err := rdb.WithContext(oneCtx).Model(&model.BaitImages{}).Where("status = ?", 0).
			Offset(offset).Limit(limit).Find(&baitImages).Error
		if err == gorm.ErrRecordNotFound {
			notFound = true
			return nil
		}
		return err
	})

	if notFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return baitImages, nil
}

func GetBaitImageById(ctx context.Context, rdb *gorm.DB, id uint32) (*model.BaitImages, error) {
	dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var baitImage model.BaitImages
	notFound := false
	err := util.RetryWithBackoff(dbCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
		defer cancel()

		err := rdb.WithContext(oneCtx).Model(&model.BaitImages{}).Where("status = ? AND id = ?", 0, id).First(&baitImage).Error
		if err == gorm.ErrRecordNotFound {
			notFound = true
			return nil
		}
		return err
	})

	if notFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &baitImage, nil
}

func CountBaitImages(ctx context.Context, rdb *gorm.DB) (int64, error) {
	dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var cnt int64
	notFound := false
	err := util.RetryWithBackoff(dbCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
		defer cancel()

		err := rdb.WithContext(oneCtx).Model(&model.BaitImages{}).Where("status = ?", 0).Count(&cnt).Error
		if err == gorm.ErrRecordNotFound {
			notFound = true
			return nil
		}
		return err
	})

	if notFound {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return cnt, nil
}

func GetBaitServices(ctx context.Context, rdb *gorm.DB, queryOptions *BaitsQueryOption, offset, limit int) ([]*model.BaitService, error) {
	dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var baitServices []*model.BaitService
	notFound := false
	err := util.RetryWithBackoff(dbCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.BaitService{}).Where("status = ?", 0).Order("created_at desc")
		if len(queryOptions.whereEqCondition) > 0 {
			db.Where(queryOptions.whereEqCondition)
		}

		if len(queryOptions.whereInCondition) > 0 {
			for column, val := range queryOptions.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s ILIKE ?", queryOptions.columnQuery.column), getLikeExpr(queryOptions.columnQuery.query))
		}

		if len(queryOptions.multicolumnQuery) > 0 {
			subDb := rdb.WithContext(oneCtx).Model(&model.BaitService{})
			for col, query := range queryOptions.multicolumnQuery {
				expr := getLikeExpr(query)
				subDb.Where(fmt.Sprintf("%s LIKE ?", col), expr)
			}
			db.Where(subDb)
		}
		if offset >= 0 && limit >= 0 {
			db.Offset(offset).Limit(limit)
		}
		err := db.Find(&baitServices).Error

		if err == gorm.ErrRecordNotFound {
			notFound = true
			return nil
		}
		return err
	})

	if notFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return baitServices, nil
}

func GetBaitService(ctx context.Context, rdb *gorm.DB, queryOptions *BaitsQueryOption) (*model.BaitService, error) {
	dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	baitService := &model.BaitService{}
	notFound := false
	err := util.RetryWithBackoff(dbCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.BaitService{}).Where("status = ?", 0)
		if len(queryOptions.whereEqCondition) > 0 {
			db.Where(queryOptions.whereEqCondition)
		}

		if len(queryOptions.whereInCondition) > 0 {
			for column, val := range queryOptions.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s ILIKE ?", queryOptions.columnQuery.column), getLikeExpr(queryOptions.columnQuery.query))
		}

		err := db.First(baitService).Error

		if err == gorm.ErrRecordNotFound {
			notFound = true
			return nil
		}
		return err
	})

	if notFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return baitService, nil
}

func DeleteBaitServiceById(ctx context.Context, rdb *gorm.DB, id uint32) error {
	dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	err := util.RetryWithBackoff(dbCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
		defer cancel()
		db := rdb.WithContext(oneCtx).Model(&model.BaitService{}).Where("status = ?", 0)

		return db.Delete(&model.BaitService{}, "id = ?", id).Error

	})
	return err
}

func CountBaitServices(ctx context.Context, rdb *gorm.DB, queryOptions *BaitsQueryOption) (int64, error) {
	dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var cnt int64
	notFound := false
	err := util.RetryWithBackoff(dbCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.BaitService{}).Where("status = ?", 0)
		if len(queryOptions.whereEqCondition) > 0 {
			db.Where(queryOptions.whereEqCondition)
		}

		if len(queryOptions.whereInCondition) > 0 {
			for column, val := range queryOptions.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s ILIKE ?", queryOptions.columnQuery.column), getLikeExpr(queryOptions.columnQuery.query))
		}
		if len(queryOptions.multicolumnQuery) > 0 {
			subDb := rdb.WithContext(oneCtx).Model(&model.BaitService{})
			for col, query := range queryOptions.multicolumnQuery {
				expr := getLikeExpr(query)
				subDb.Where(fmt.Sprintf("%s LIKE ?", col), expr)
			}
			db.Where(subDb)
		}

		err := db.Count(&cnt).Error
		if err == gorm.ErrRecordNotFound {
			notFound = true
			return nil
		}
		return err
	})

	if notFound {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return cnt, nil
}

func UpsertBaitService(ctx context.Context, rdb *gorm.DB, bait *model.BaitService) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	logging.GetLogger().Info().Msgf("upsert bait service %+v", bait)
	err := rdb.WithContext(oneCtx).Model(&model.BaitService{}).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForBait),
	}).Create(bait).Error
	if err != nil {
		return err
	}
	return nil
}

func InsertBaitService(ctx context.Context, rdb *gorm.DB, bait *model.BaitService) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	logging.GetLogger().Info().Msgf("upsert bait service %+v", bait)
	err := rdb.WithContext(oneCtx).Model(&model.BaitService{}).Create(bait).Error
	if err != nil {
		return err
	}
	return nil
}

func UpdateBaitService(ctx context.Context, rdb *gorm.DB, bait *model.BaitService) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	err := rdb.WithContext(oneCtx).Model(&model.BaitService{}).Where("id = ?", bait.ID).Updates(bait).Error
	if err != nil {
		return err
	}
	return nil
}
