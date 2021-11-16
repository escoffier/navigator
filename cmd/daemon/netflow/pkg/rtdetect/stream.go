package rtdetect

import (
	"context"
	"io"
	"strconv"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/falcosecurity/client-go/pkg/client"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"google.golang.org/grpc"
)

const (
	timeout    = 1 * time.Second
	bufferSize = 100
)

type ClusterManager interface {
	ClusterKey() (string, bool)
}

type EventHandler interface {
	Put(ctx context.Context, event eventItem) error
	CheckTarget(ctx context.Context, event eventItem) bool
}
type RuntimeEventStream struct {
	unixSocketPath string
	nodeName       string
	clusterManager ClusterManager
	rtClient       *client.Client

	handlers []EventHandler
}

type Builder struct {
	unixSocketPath string
	nodeName       string
	handlers       []EventHandler
	cm             ClusterManager
}

func StreamBuilder(unixSocketPath, nodeName string, cm ClusterManager) *Builder {
	return &Builder{
		unixSocketPath: unixSocketPath,
		nodeName:       nodeName,
		handlers:       make([]EventHandler, 0, 2),
		cm:             cm,
	}
}

func (b *Builder) WithHandler(h EventHandler) *Builder {
	b.handlers = append(b.handlers, h)
	return b
}

func (b *Builder) Build(ctx context.Context) (*RuntimeEventStream, error) {
	return newRuntimeEventStream(ctx, b.unixSocketPath, b.nodeName, b.cm, b.handlers)
}
func newRuntimeEventStream(ctx context.Context, unixSocketPath, nodeName string, cm ClusterManager, handlers []EventHandler) (*RuntimeEventStream, error) {
	rt, err := client.NewForConfig(ctx, &client.Config{
		UnixSocketPath: unixSocketPath,
	})
	if err != nil {
		return nil, err
	}

	return &RuntimeEventStream{
		unixSocketPath: unixSocketPath,
		rtClient:       rt,
		nodeName:       nodeName,
		clusterManager: cm,
		handlers:       handlers,
	}, nil
}

func (s *RuntimeEventStream) Close() error {
	return s.rtClient.Close()
}

func (s *RuntimeEventStream) generateUUID(resp *outputs.Response) int64 {
	var timestamp int64
	if resp.Time == nil {
		timestamp = time.Now().UnixNano()
	} else {
		timestamp = resp.Time.AsTime().UnixNano()
	}
	return util.GenerateUUID64Signed(s.nodeName, resp.Rule, resp.Output, strconv.FormatInt(timestamp, 10))
}
func (s *RuntimeEventStream) callback(res *outputs.Response) error {
	ckey, ok := s.clusterManager.ClusterKey()
	if !ok {
		ckey = "-"
	}
	ctx := context.Background()
	item := eventItem{
		data:       res,
		uuid:       s.generateUUID(res),
		clusterKey: ckey,
	}

	for _, ah := range s.handlers {
		if ah.CheckTarget(ctx, item) {
			ah.Put(ctx, item)
		}
	}
	return nil
}

func (s *RuntimeEventStream) outputsWatch(ctx context.Context, opts ...grpc.CallOption) error {
	ocli, err := s.rtClient.Outputs()
	if err != nil {
		return err
	}

	fcs, err := ocli.Sub(ctx, opts...)
	if err != nil {
		return err
	}

	resCh := make(chan *outputs.Response, bufferSize)
	errCh := make(chan error, bufferSize)

	go func() {
		defer close(resCh)
		defer close(errCh)
		for {
			res, err := fcs.Recv()
			if err != nil {
				errCh <- err
				return
			}
			resCh <- res
		}
	}()

	for {
		select {
		case res, more := <-resCh:
			if !more {
				return nil
			}

			err := s.callback(res)
			if err != nil {
				return err
			}
		case err := <-errCh:
			if err == io.EOF {
				return nil
			}
			return err
		case <-time.After(timeout):
			fcs.Send(&outputs.Request{})
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
func (s *RuntimeEventStream) Start(ctx context.Context) error {
	contErrCnt := 0
	sleepDur := 50 * time.Millisecond
	for {
		if err := s.outputsWatch(ctx); err != nil {
			logging.GetLogger().Err(err).Msg("OutputsWatch error")
			contErrCnt++
			if contErrCnt > 10 {
				if sleepDur*2 <= 10*time.Second {
					sleepDur *= 2
				}
				contErrCnt = 0
			}
			time.Sleep(sleepDur)
		}
	}
}
