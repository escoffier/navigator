package heavyagent

import (
	"context"
)

type Handler interface {
	Handle(ctx context.Context, obj interface{}) error
}
