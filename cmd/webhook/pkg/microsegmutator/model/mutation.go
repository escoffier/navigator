package model

import (
	"context"
	//"gitlab.com/tensorsecurity-rd/tensor-webhook/pkg/microsegmutator/"
)

func (t *mutationModel) GetResourceByID(ctx context.Context, ID uint32) (TensorMicrosegResource, error) {
	resource := TensorMicrosegResource{}
	err := t.db.WithContext(ctx).Where("id = ?", ID).First(&resource).Error
	return resource, err
}
