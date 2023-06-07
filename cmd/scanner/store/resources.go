package store

import (
	"context"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (dal *ResourceDao) SearchCluster(ctx context.Context, clusterKey string) (*model.TensorCluster, error) {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()
	var cluster model.TensorCluster
	if err := dal.db.Get().WithContext(timeoutCtx).Model(new(model.TensorCluster)).
		Where("id = ?", clusterKey).First(&cluster).Error; err != nil {
		return nil, err
	}

	return &cluster, nil
}

type ResourceDal interface {
	SearchCluster(ctx context.Context, clusterKey string) (*model.TensorCluster, error)
	SearchResources(ctx context.Context, imageUUID []uint32) ([]*imagesec.ImageContainerResources, error)
}

type ResourceDao struct {
	db *databases.RDBInstance
}

func NewResourceDao(db *databases.RDBInstance) *ResourceDao {
	return &ResourceDao{db: db}
}

type TensorResources struct {
	ImageUUID    uint32
	Name         string
	ResourceName string
	Namespace    string
	ClusterKey   string
	ClusterName  string
}

func (dal *ResourceDao) SearchResources(ctx context.Context, imageUUID []uint32) ([]*imagesec.ImageContainerResources, error) {

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	imageUUID = util.DuplicateUint32Slice(imageUUID)
	res := make([]model.TensorContainer, 0)
	if len(imageUUID) == 0 {
		return make([]*imagesec.ImageContainerResources, 0), nil
	}

	db := dal.db.Get().WithContext(ctx)
	db = db.Model(new(model.TensorContainer)).Where("image_uuid IN ? ", imageUUID).Where("status = 0")

	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}

	// 再查集群名
	clusters := make([]model.TensorCluster, 0)
	err := dal.db.Get().WithContext(ctx).Model(new(model.TensorCluster)).Find(&clusters).Error
	if err != nil {
		return nil, err
	}
	// 数据不多，两层循环
	ans := make([]*imagesec.ImageContainerResources, len(res))
	for i := range ans {
		ans[i] = &imagesec.ImageContainerResources{
			ImageUUID:    res[i].ImageUUID,
			Name:         res[i].Name,
			ResourceName: res[i].ResourceName,
			Namespace:    res[i].Namespace,
			ClusterKey:   res[i].ClusterKey,
		}
	}
	// 数据不多，两层循环
	for i := range ans {
		for j := range clusters {
			if ans[i].ClusterKey == clusters[j].Key {
				ans[i].ClusterName = clusters[j].Name
				break
			}
		}
	}

	return ans, nil
}

type ScanTaskDal interface {
	GetSubTasks(ctx context.Context, param SearchSubTaskParam, filter *model.Filter) ([]model.SubTask, int64, error)
	GetTaskList(ctx context.Context, param SearchTaskParam, filter *model.Filter) ([]model.Task, int64, error)
}
