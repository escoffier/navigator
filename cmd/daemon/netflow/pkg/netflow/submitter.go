package netflow

import (
	"context"
	"errors"
	"runtime/debug"
	"time"

	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type SubmitFunc func(context.Context, []*model.TensorNetworkFlow) error
type Submitter struct {
	submitInterval time.Duration

	flowChan chan *model.TensorNetworkFlow

	submitFunc SubmitFunc
}

func NewSubmitter(intv time.Duration, submitFunc SubmitFunc) *Submitter {
	s := &Submitter{
		submitInterval: intv,
		submitFunc:     submitFunc,
		flowChan:       make(chan *model.TensorNetworkFlow, 50),
	}
	s.asyncLoop()
	return s
}
func (s *Submitter) Submit(ctx context.Context, flow *model.TensorNetworkFlow) error {
	tctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	select {
	case s.flowChan <- flow:
		return nil
	case <-tctx.Done():
		return errors.New("submit timeout")
	}
}

func (s *Submitter) submitData(flows []*model.TensorNetworkFlow) error {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("panic for submitter: %v. stack: %s", r, debug.Stack())
		}
	}()

	err := s.submitFunc(context.Background(), flows)
	if err != nil {
		log.Errorf("Submit network flows error: %v. flows: %v", err, flows)
	}
	return err
}

func (s *Submitter) asyncLoop() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("panic for submitter: %v. stack: %s", r, debug.Stack())
			}
		}()

		ticker := time.NewTicker(s.submitInterval)
		defer ticker.Stop()

		flowMap := make(map[uint32]*model.TensorNetworkFlow, 500)
		for {
			select {
			case flow := <-s.flowChan:
				if flow.UUID > 0 {
					flowMap[flow.UUID] = flow
				}
			case <-ticker.C:
				flows := make([]*model.TensorNetworkFlow, 0, len(flowMap))
				for _, flow := range flowMap {
					flows = append(flows, flow)
				}

				go s.submitData(flows)
				// clear buffer
				flowMap = make(map[uint32]*model.TensorNetworkFlow, len(flowMap)+10)
			}
		}
	}()
}
