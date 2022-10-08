package netflow

import (
	"context"
	"errors"
	"runtime/debug"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type SubmitFunc func(context.Context, []*model.TensorNetworkFlow) error
type Submitter struct {
	submitInterval time.Duration
	maxBufferSize  int
	submitFunc     SubmitFunc

	flowChan chan *model.TensorNetworkFlow
}

func NewSubmitter(intv time.Duration, maxBufferSize int, submitFunc SubmitFunc) *Submitter {
	if intv == 0 {
		intv = 1 * time.Minute
	}
	if maxBufferSize <= 0 {
		maxBufferSize = 1024
	}
	s := &Submitter{
		submitInterval: intv,
		maxBufferSize:  maxBufferSize,
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
			logging.GetLogger().Error().Msgf("panic for submitter: %v. stack: %s", r, debug.Stack())
		}
	}()

	err := s.submitFunc(context.Background(), flows)
	if err != nil {
		logging.GetLogger().Error().Msgf("Submit network flows error: %v. flows: %v", err, flows)
	}
	return err
}

func (s *Submitter) submitBuffer(flowMap map[uint32]*model.TensorNetworkFlow) {
	if s.submitFunc == nil {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("panic for submitBuffer: %v. stack: %s", r, debug.Stack())
		}
	}()

	flows := make([]*model.TensorNetworkFlow, 0, len(flowMap))
	for _, flow := range flowMap {
		flows = append(flows, flow)
	}

	go func() {
		err := s.submitData(flows)
		if err != nil {
			logging.GetLogger().Error().Msgf("submit data error, %v", err)
		}
	}()
}
func (s *Submitter) asyncLoop() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("panic for submitter: %v. stack: %s", r, debug.Stack())
			}
		}()
		ticker := time.NewTicker(s.submitInterval)
		defer ticker.Stop()

		flowMap := make(map[uint32]*model.TensorNetworkFlow, s.maxBufferSize)
		for {
			select {
			case flow := <-s.flowChan:
				if flow.UUID > 0 {
					flowMap[flow.UUID] = flow
				}
				fmSize := len(flowMap)
				if fmSize >= s.maxBufferSize {
					s.submitBuffer(flowMap)
					flowMap = make(map[uint32]*model.TensorNetworkFlow, s.maxBufferSize)
				}
			case <-ticker.C:
				s.submitBuffer(flowMap)
				flowMap = make(map[uint32]*model.TensorNetworkFlow, len(flowMap))
			}
		}
	}()
}
