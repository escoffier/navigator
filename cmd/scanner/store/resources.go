package store

import (
	"context"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type PodResourceRelationDal interface {
	Search(ctx context.Context, nameSpace, clusterKey, podName string) ([]model.PodResourceRelation, error)
}

type PodResourceRelationDao struct {
	db *databases.RDBInstance
}

func (s *PodResourceRelationDao) Search(ctx context.Context, nameSpace, clusterKey, podName string) ([]model.PodResourceRelation, error) {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()
	res := make([]model.PodResourceRelation, 0)
	err := s.db.Get().WithContext(timeoutCtx).Model(new(model.PodResourceRelation)).
		Where("namespace = ? AND cluster_key = ? AND pod_name = ? ", nameSpace, clusterKey, podName).Find(&res).Error
	return res, err
}

func NewPodResourceRelationDao(db *databases.RDBInstance) *PodResourceRelationDao {
	return &PodResourceRelationDao{db: db}
}

type ResourceDal interface {
	SearchResources(ctx context.Context, imageUUID []uint32) ([]*model.ImageContainerResources, error)
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

func (dal *ResourceDao) SearchResources(ctx context.Context, imageUUID []uint32) ([]*model.ImageContainerResources, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx)
	db = db.Model(new(model.TensorContainer)).Where("image_uuid IN ? ", imageUUID).Where("status = 0")
	res := make([]model.TensorContainer, 0)
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
	ans := make([]*model.ImageContainerResources, len(res))
	for i := range ans {
		ans[i] = &model.ImageContainerResources{
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
