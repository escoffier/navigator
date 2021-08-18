package model

import (
	"context"
)

type Model interface {
	GetResourceByID(ctx context.Context, ID uint32) (TensorMicrosegResource, error)
}
