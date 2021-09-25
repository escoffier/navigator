package rtdetect

import (
	"context"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/falcosecurity/client-go/pkg/client"
)

const (
	timeout = 3 * time.Second
)

type RuntimeEventStream struct {
	unixSocketPath string
	rtClient       *client.Client

	handlers []*AsyncHandler
}

type Builder struct {
	unixSocketPath string
	handlers       []*AsyncHandler
}

func StreamBuilder(unixSocketPath string) *Builder {
	return &Builder{
		unixSocketPath: unixSocketPath,
		handlers:       make([]*AsyncHandler, 0, 2),
	}
}

func (b *Builder) WithHandler(h *AsyncHandler) *Builder {
	b.handlers = append(b.handlers, h)
	return b
}

func (b *Builder) Build(ctx context.Context) (*RuntimeEventStream, error) {
	return newRuntimeEventStream(ctx, b.unixSocketPath, b.handlers)
}
func newRuntimeEventStream(ctx context.Context, unixSocketPath string, handlers []*AsyncHandler) (*RuntimeEventStream, error) {
	rt, err := client.NewForConfig(ctx, &client.Config{
		UnixSocketPath: unixSocketPath,
	})
	if err != nil {
		return nil, err
	}

	return &RuntimeEventStream{
		unixSocketPath: unixSocketPath,
		rtClient:       rt,
		handlers:       handlers,
	}, nil
}

func (s *RuntimeEventStream) Close() error {
	return s.rtClient.Close()
}

func (s *RuntimeEventStream) callback(res *outputs.Response) error {
	for _, ah := range s.handlers {
		ah.Put(context.Background(), eventItem{
			data: res,
		})
	}
	return nil
}
func (s *RuntimeEventStream) Start(ctx context.Context) error {
	return s.rtClient.OutputsWatch(ctx, s.callback, timeout)
}
