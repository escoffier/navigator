package model

import (
	"context"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	//"gitlab.com/tensorsecurity-rd/tensor-webhook/pkg/microsegmutator/"
)

func (t *mutationModel) GetResourceByID(ctx context.Context, ID uint32) (model.TensorMicrosegResource, error) {
	resource := model.TensorMicrosegResource{}
	err := t.db.WithContext(ctx).Where("id = ?", ID).First(&resource).Error
	return resource, err
}

func (t *mutationModel) GetClusterByName(ctx context.Context, name string) (*model.TensorCluster, error) {
	cluster := model.TensorCluster{}
	err := t.db.WithContext(ctx).Where("name = ?", name).First(&cluster).Error
	return &cluster, err
}

func (t mutationModel) GetPodRelation(ctx context.Context, clusterKey, namespace, name string) (*model.PodResourceRelation, error) {
	pod := model.PodResourceRelation{}
	err := t.db.WithContext(ctx).Where("cluster_key = ? and namespace = ? and pod_name = ?", clusterKey, namespace, name).First(&pod).Error
	return &pod, err
}
