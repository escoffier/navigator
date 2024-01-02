package imagesecStore

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type DetectPolicyDal interface {
	CreateDetectPolicy(ctx context.Context, data *imagesecModel.SecurityPolicy) error
	DeleteDetectPolicy(ctx context.Context, policyID int64) error
	UpdateDetectPolicy(ctx context.Context, param imagesecModel.UpdateSecurityPolicyParam) error
	SearchDetectPolicy(ctx context.Context, param imagesecModel.SearchSecurityPolicyParam) ([]*imagesecModel.SecurityPolicy, int64, error)
	SearchDetectPolicySnapshot(ctx context.Context, param imagesecModel.SearchSecurityPolicyParam) ([]imagesecModel.SecurityPolicy, error)
	CreateDetectPolicySnapshot(ctx context.Context, data *imagesecModel.SecurityPolicy) error
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
	err := dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).Create(data).Error
	if err != nil {
		return err
	}

	return nil
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

	db = db.Where("id = ?", param.ID)

	if !param.UpdateDefault {
		db = db.Where("is_default = ?", false)
	}

	if len(param.Updater) > 0 {
		if err := db.Updates(param.Updater).Error; err != nil {
			return nil
		}
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

	regs := make([]imagesecModel.Registry, 0)
	if err := dal.db.Get().WithContext(cancelCtx).Table(new(imagesecModel.Registry).TableName()).
		Find(&regs).Error; err != nil {
		return nil, 0, err
	}

	regMap := make(map[int64]string)
	for i := range regs {
		if param.JustRegName {
			regMap[regs[i].ID] = regs[i].Name
		} else {
			regMap[regs[i].ID] = fmt.Sprintf("%s(%s)", regs[i].Name, regs[i].Url)
		}
	}

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesecModel.SecurityPolicy).TableName())

	if len(param.Ids) > 0 {
		db = db.Where("id IN ?", param.Ids)
	}
	if len(param.Filed) > 0 {
		db = db.Select(param.Filed)
	}
	if param.Deleted == consts.FalseString {
		db = db.Where("deleted_at = ?", 0)
	} else if param.Deleted == consts.TrueString {
		db = db.Where("deleted_at > ?", 0)
	}

	if util.ExistInStringSlice(param.Enable, consts.TrueString) && util.ExistInStringSlice(param.Enable, consts.FalseString) {
		param.Enable = make([]string, 0)
	}

	if len(param.Enable) > 0 && param.Enable[0] == consts.TrueString {
		db = db.Where("enable = ?", true)
	} else if len(param.Enable) > 0 && param.Enable[0] == consts.FalseString {
		db = db.Where("enable = ?", false)
	}
	if param.Default == consts.TrueString {
		db = db.Where("is_default = ?", true)
	} else if param.Default == consts.FalseString {
		db = db.Where("is_default = ?", false)
	}

	if param.Keyword != "" {
		db = db.Where("name LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword))
	}
	if param.PolicyType != "" {
		db = db.Where("policy_type = ? ", param.PolicyType)
	}
	if util.ExistInStringSlice(param.DeployMod, imagesecModel.ImageSafeString) && util.ExistInStringSlice(param.DeployMod, imagesecModel.BaseImageTypeString) {
		param.DeployMod = make([]string, 0)
	}
	if len(param.DeployMod) > 0 && param.DeployMod[0] != "" {
		db = db.Where("deploy_mod = ? ", param.DeployMod[0])
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

	db = imagesecModel.AddFilter(db, param.Filter)
	res := make([]*imagesecModel.SecurityPolicy, 0)
	err := db.Find(&res).Error
	if err != nil {
		return nil, 0, err
	}
	for i := range res {
		res[i].Deserialize(clusterMap, regMap)
		res[i].ChangePolicyName(ctx)
	}

	return res, cnt, err
}

func (dal *DetectPolicyDao) SearchDetectPolicySnapshot(ctx context.Context, param imagesecModel.SearchSecurityPolicyParam) ([]imagesecModel.SecurityPolicy, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	ans := make([]*imagesecModel.SecurityPolicySnapshot, 0)
	db := dal.db.Get().WithContext(cancelCtx).Model(&imagesecModel.SecurityPolicySnapshot{})
	if param.UniqueID > 0 {
		db = db.Where("unique_id = ?", param.UniqueID)
	}
	if len(param.UniqueIds) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueIds)
	}
	if len(param.Filed) > 0 {
		db = db.Select(param.Filed)
	}

	db = imagesecModel.AddFilter(db, param.Filter)
	err := db.Find(&ans).Error

	if err != nil {
		return nil, err
	}
	res := make([]imagesecModel.SecurityPolicy, 0)
	for i := range ans {
		ans[i].Deserialize()
		res = append(res, ans[i].SecurityPolicy)
	}
	return res, nil
}

func (dal *DetectPolicyDao) CreateDetectPolicySnapshot(ctx context.Context, data *imagesecModel.SecurityPolicy) error {

	sna := &imagesecModel.SecurityPolicySnapshot{
		UniqueID:       data.UniqueID,
		PolicyID:       data.ID,
		SecurityPolicy: *data,
	}
	sna.Serialize()
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	return dal.db.Get().WithContext(cancelCtx).Model(imagesecModel.SecurityPolicySnapshot{}).Create(sna).Error
}
