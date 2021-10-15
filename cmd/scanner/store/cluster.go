package store

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

type PodResourceRelationInterface interface {
	Search(ctx context.Context, nameSpace, clusterKey, podName string) ([]model.PodResourceRelation, error)
}

type PodResourceRelationDao struct {
	db *rdbtools.GormWrapper
}

func (s *PodResourceRelationDao) Search(ctx context.Context, nameSpace, clusterKey, podName string) ([]model.PodResourceRelation, error) {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()
	res := make([]model.PodResourceRelation, 0)
	err := s.db.Get().WithContext(timeoutCtx).Model(new(model.PodResourceRelation)).Where("namespace = ? AND cluster_key = ? AND pod_name = ? ", nameSpace, clusterKey, podName).Find(&res).Error
	return res, err
}

func NewPodResourceRelationDao(db *rdbtools.GormWrapper) *PodResourceRelationDao {
	return &PodResourceRelationDao{db: db}
}
