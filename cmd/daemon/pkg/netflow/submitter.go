package netflow

import (
	"context"
	"errors"
	"math/rand"
	"runtime/debug"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/security-rd/go-pkg/model"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
)

type SubmitFunc func(context.Context, []*model.TensorNetworkFlow) error

type Submitter struct {
	submitInterval time.Duration
	flowChan       chan *model.TensorNetworkFlow
	submitFunc     SubmitFunc
	Palace         palace.Palace
}

func NewSubmitter(intv time.Duration, submitFunc SubmitFunc) *Submitter {
	Palace, err := palace.Init()
	if err != nil {
		logging.GetLogger().Error().Msgf("init palace failed, %+v.", err)
		return nil
	}

	s := &Submitter{
		submitInterval: intv,
		submitFunc:     submitFunc,
		flowChan:       make(chan *model.TensorNetworkFlow, 50),
		Palace:         Palace,
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

		timestamp := time.Duration(s.submitInterval.Seconds() + float64(rand.Intn(120)))
		ticker := time.NewTicker(timestamp * time.Second)
		defer ticker.Stop()

		flowMap := make(map[uint64]*model.TensorSimpleNetworkFlow, 500)
		for {
			select {
			case flow := <-s.flowChan:
				sflow, ok := flowMap[flow.UUID]
				if !ok {
					flowMap[flow.UUID] = &model.TensorSimpleNetworkFlow{
						UUID:      flow.UUID,
						Increment: 0,
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					}
					//post
					err := s.Palace.SendOneNetworkFlow(*flow)
					if err != nil {
						logging.GetLogger().Err(err).Msg("post net flow data failed.")
					}
				} else {
					sflow.Increment += 1
					sflow.UpdatedAt = time.Now()
				}

			case <-ticker.C:
				for _, flow := range flowMap {
					//filter
					if time.Now().Unix()-flow.CreatedAt.Unix() < 300 {
						continue
					}
					//delete invalid data
					if flow.Increment == 0 {
						delete(flowMap, flow.UUID)
						continue
					}
					//post
					err := s.Palace.SendIncrementNetworkFlow(*flow)
					if err != nil {
						logging.GetLogger().Err(err).Msgf("send net increment failed.")
						continue
					}
					//delete
					delete(flowMap, flow.UUID)
				}
			}
		}
	}()
}
