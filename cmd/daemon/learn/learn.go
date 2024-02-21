package learn

import (
	"context"
	"sync"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
)

type Learn struct {
	learningHandler *LearningHandler
	cim             *k8s.ClusterInfoManager
	npw             *nodeinfo.NodePodsWatcher
	pri             *nodeinfo.PodResInfo
	mq              mq.Writer
}

func New(opts ...OptionFunc) (*Learn, error) {
	l := &Learn{}
	for _, opt := range opts {
		opt(l)
	}

	learningHandler, err := NewLearningHandler(l.cim, l.mq, l.npw, l.pri)
	if err != nil {
		return nil, err
	}
	l.learningHandler = learningHandler

	return l, nil
}

func (l *Learn) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	// listen for learning events
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("panic: %v", r)
			}
		}()
		err := l.learningHandler.StartLearning()
		if err != nil {
			logging.GetLogger().Error().Msgf("startLearning: %v", err)
		}
	}()
	wg.Wait()
	return nil
}

func (l *Learn) Help() {
	logging.GetLogger().Info().Msg("learn help")
}

func (l *Learn) Clean() {
	logging.GetLogger().Info().Msg("learn clean")
}
