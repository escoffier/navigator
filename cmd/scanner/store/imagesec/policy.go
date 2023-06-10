package imagesec

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type DetectPolicyDal interface {
	CreateDetectPolicy(ctx context.Context, data *imagesecModel.SecurityPolicy) error
	DeleteDetectPolicy(ctx context.Context, policyID int64) error
	UpdateDetectPolicy(ctx context.Context, param imagesecModel.UpdateSecurityPolicyParam) error
	SearchDetectPolicy(ctx context.Context, param imagesecModel.SearchSecurityPolicyParam) ([]*imagesecModel.SecurityPolicy, int64, error)
}

type DetectPolicyDao struct {
	db *databases.RDBInstance
}

func NewDetectPolicyDao(db *databases.RDBInstance) *DetectPolicyDao {
	return &DetectPolicyDao{db: db}
}

func (dal *DetectPolicyDao) CreateDetectPolicy(ctx context.Context, data *imagesecModel.SecurityPolicy) error {
	data.Serialize()
	if err := data.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	return dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).Create(data).Error
}

func (dal *DetectPolicyDao) DeleteDetectPolicy(ctx context.Context, policyID int64) error {
	policies, _, err := dal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{Ids: []int64{policyID}})
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		return nil
	}
	if policies[0].IsDefault {
		return fmt.Errorf("deleting the default policy is not allowed")
	}

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesecModel.SecurityPolicy).TableName()).
		Where("id = ?", policyID)
	return db.Delete(&imagesecModel.SecurityPolicy{ID: policyID}).Error
}

func (dal *DetectPolicyDao) UpdateDetectPolicy(ctx context.Context, param imagesecModel.UpdateSecurityPolicyParam) error {

	if err := param.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesecModel.SecurityPolicy).TableName())
	db = db.Where("id = ?", param.ID).Where("is_default = ?", false).Where("deleted_at = ?", 0)

	if len(param.Updater) > 0 {
		return db.Updates(param.Updater).Error
	}
	return nil
}

func (dal *DetectPolicyDao) SearchDetectPolicy(ctx context.Context, param imagesecModel.SearchSecurityPolicyParam) (
	[]*imagesecModel.SecurityPolicy, int64, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	// 要查集群名，又因为集群名是可以修改的
	clusters := make([]model.TensorCluster, 0)
	if err := dal.db.Get().WithContext(cancelCtx).Table(new(model.TensorCluster).TableName()).Select("id", "name").
		Find(&clusters).Error; err != nil {
		return nil, 0, err
	}

	clusterMap := make(map[string]string)
	for i := range clusters {
		clusterMap[clusters[i].Key] = clusters[i].Name
	}

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesecModel.SecurityPolicy).TableName())

	if len(param.Ids) > 0 {
		db = db.Where("id IN ?", param.Ids)
	}
	if param.Deleted == consts.FalseString {
		db = db.Where("deleted_at = ?", 0)
	} else if param.Deleted == consts.TrueString {
		db = db.Where("deleted_at > ?", 0)
	}

	if param.Default == consts.TrueString {
		db = db.Where("is_default = ?", true)
	} else if param.Default == consts.FalseString {
		db = db.Where("is_default = ?", false)
	}

	if param.Keyword != "" {
		db = db.Where("name LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword))
	}
	var cnt int64

	if !param.NotCount {
		if err := db.Count(&cnt).Error; err != nil {
			return nil, cnt, err
		}
	}

	if param.ImageDetect != nil && param.ImageDetect.ImageID > 0 {
		sub := dal.db.Get().WithContext(cancelCtx).Table(new(imagesecModel.ImageDetectBrief).TableName()).
			Select("distinct policy_id").Where("image_id = ?", param.ImageDetect.ImageID)
		if param.ImageDetect.Flag > 0 {
			sub = sub.Where("flag = ?", param.ImageDetect.Flag)
		}
		db = db.Where("id IN ( ? )", sub)
	}

	db = model.AddFilter(db, param.Filter)
	res := make([]*imagesecModel.SecurityPolicy, 0)
	err := db.Find(&res).Error
	if err != nil {
		return nil, 0, err
	}
	for i := range res {
		res[i].Deserialize(clusterMap)
		res[i].ChangePolicyName(ctx)
	}

	return res, cnt, err
}
