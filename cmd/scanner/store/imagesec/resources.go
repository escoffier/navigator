package imagesecStore

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ResourceDal interface {
	SearchClusterName(ctx context.Context, clusterKey []string) (map[string]string, error)
	SearchResources(ctx context.Context, param imagesec.SearchResourceParam) ([]*imagesec.RawContainer, int64, error)
}

type ResourceDao struct {
	db *databases.RDBInstance
}

func NewResourceDao(db *databases.RDBInstance) *ResourceDao {
	return &ResourceDao{db: db}
}

func (dal *ResourceDao) SearchResources(ctx context.Context, param imagesec.SearchResourceParam) ([]*imagesec.RawContainer, int64, error) {

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Table(new(model.TensorRawContainer).TableName())
	if !param.NotFilterStatus {
		db = db.Where("status < ? ", assets.ActiveCRIState)
	}
	if param.ImageUUID > 0 {
		db = db.Where("image_uuid = ?", param.ImageUUID)
	}
	if param.StartID != "" {
		db = db.Where("id > ?", param.StartID)
	}

	if param.Running == consts.TrueString {
		db = db.Where("status = 0")
	}

	if len(param.ImageUUIDs) > 0 {
		db = db.Where("image_uuid IN ?", param.ImageUUIDs)
	}
	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
	}

	if param.VulnUniqueID > 0 {
		vu := imagesec.VulnToImage{}
		im := imagesec.Image{}
		sub1 := dal.db.Get().WithContext(ctx).Table(vu.TableName()).Where("unique_target = ?").Select("image_unique_id")
		sub2 := dal.db.Get().WithContext(ctx).Table(im.TableName()).Where("unique_id in (?)", sub1).Select("image_uuid")
		db = db.Where("image_uuid in (?)", sub2)
	}
	if param.PkgUniqueID > 0 {
		vu := imagesec.PkgToImage{}
		im := imagesec.Image{}
		sub1 := dal.db.Get().WithContext(ctx).Table(vu.TableName()).Where("unique_target = ?").Select("image_unique_id")
		sub2 := dal.db.Get().WithContext(ctx).Table(im.TableName()).Where("unique_id in (?)", sub1).Select("image_uuid")
		db = db.Where("image_uuid in (?)", sub2)
	}
	if param.WebshellMD5 != "" {
		sub1 := dal.db.Get().WithContext(ctx).Table(new(imagesec.Webshell).TableName()).Select("unique_id").Where("md5 = ?", param.WebshellMD5)
		sub2 := dal.db.Get().WithContext(ctx).Table(new(imagesec.WebshellToImage).TableName()).Select("image_unique_id").Where("unique_target IN ( ? )", sub1)
		sub3 := dal.db.Get().WithContext(ctx).Table(new(imagesec.Image).TableName()).Where("unique_id IN ( ? )", sub2).Select("image_uuid")
		db = db.Where("image_uuid in (?)", sub3)
	}

	if param.MalwareMD5 != "" {
		sub1 := dal.db.Get().WithContext(ctx).Table(new(imagesec.Malware).TableName()).Select("unique_id").Where("hash = ?", param.MalwareMD5)
		sub2 := dal.db.Get().WithContext(ctx).Table(new(imagesec.MalwareToImage).TableName()).Select("image_unique_id").Where("unique_target IN ( ? )", sub1)
		sub3 := dal.db.Get().WithContext(ctx).Table(new(imagesec.Image).TableName()).Where("unique_id IN ( ? )", sub2).Select("image_uuid")
		db = db.Where("image_uuid in (?)", sub3)
	}

	// 查询过重，需要优化
	if param.SensitiveMD5 != "" {
		sub1 := dal.db.Get().WithContext(ctx).Table(new(imagesec.SensitiveFile).TableName()).Select("unique_id").Where("md5 = ?", param.SensitiveMD5)
		sub2 := dal.db.Get().WithContext(ctx).Table(new(imagesec.SensitiveToImage).TableName()).Select("image_unique_id").Where("unique_target IN ( ? )", sub1)
		sub3 := dal.db.Get().WithContext(ctx).Table(new(imagesec.Image).TableName()).Where("unique_id IN ( ? )", sub2).Select("image_uuid")
		db = db.Where("image_uuid in (?)", sub3)
	}
	if param.ImageID > 0 {
		sub3 := dal.db.Get().WithContext(ctx).Table(new(imagesec.Image).TableName()).Where("id = ?", param.ImageID).Select("image_uuid")
		db = db.Where("image_uuid in (?)", sub3)
	}
	if param.ImageUniqueID > 0 {
		sub3 := dal.db.Get().WithContext(ctx).Table(new(imagesec.Image).TableName()).Where("unique_id = ?", param.ImageUniqueID).Select("image_uuid")
		db = db.Where("image_uuid in (?)", sub3)
	}
	if param.Keyword != "" {
		db = db.Where("name LIKE ? OR resource_name LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword), fmt.Sprintf("%%%s%%", param.Keyword))
	}

	res := make([]model.TensorRawContainer, 0)
	var cnt int64
	if !param.NotNeedCont {
		if err := db.Count(&cnt).Error; err != nil {
			return nil, 0, err
		}
	}
	db = imagesec.AddFilter(db, param.Filter)

	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	ans := make([]*imagesec.RawContainer, 0)
	for i := range res {
		ans = append(ans, &imagesec.RawContainer{
			TensorRawContainer: res[i],
		})
	}

	return ans, cnt, nil
}

func (dal *ResourceDao) SearchClusterName(ctx context.Context, clusterKey []string) (map[string]string, error) {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()
	clusterName := make(map[string]string)
	cluster := make([]model.TensorCluster, 0)
	if err := dal.db.Get().WithContext(timeoutCtx).Model(new(model.TensorCluster)).
		Where("id IN ?", clusterKey).Find(&cluster).Error; err != nil {
		return clusterName, err
	}
	for i := range cluster {
		clusterName[cluster[i].Key] = cluster[i].Name
	}
	return clusterName, nil
}
