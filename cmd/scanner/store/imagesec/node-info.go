package imagesec

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type NodeInfoDal interface {
	CreateNodeInfo(ctx context.Context, data *imagesec.NodeInfo) error
	SearchNodeInfo(ctx context.Context, param imagesec.SearchNodeInfoParam) ([]*imagesec.NodeInfo, int64, error)
}

type NodeReportDao struct {
	db *databases.RDBInstance
}

func (dal *NodeReportDao) CreateNodeInfo(ctx context.Context, data *imagesec.NodeInfo) error {
	if err := data.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	pre := make([]*imagesec.NodeInfo, 0)
	if err := dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).
		Where("unique_id = ?", data.UniqueID).Find(&pre).Error; err != nil {
		return err
	}

	if len(pre) > 0 {
		return nil
	}
	db := dal.db.Get().WithContext(cancelCtx).Table(data.TableName())
	if err := db.Create(data).Error; err != nil {
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return nil
		}
		return err
	}
	return nil
}

func (dal *NodeReportDao) SearchNodeInfo(ctx context.Context, param imagesec.SearchNodeInfoParam) ([]*imagesec.NodeInfo, int64, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesec.NodeInfo).TableName())
	if param.Keyword != "" {
		db = db.Where("hostname LIKE ?  OR ip LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword),
			fmt.Sprintf("%%%s%%", param.Keyword))
	}
	if len(param.Ids) > 0 {
		db = db.Where("id IN ?", param.Ids)
	}
	if len(param.UniqueIds) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueIds)
	}

	// 先查总数
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	res := make([]*imagesec.NodeInfo, 0)
	db = model.AddFilter(db, param.Filter)
	err := db.Find(&res).Error
	return res, cnt, err
}

func NewNodeReportDao(db *databases.RDBInstance) *NodeReportDao {
	return &NodeReportDao{db: db}
}
