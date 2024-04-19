package netflow

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/model"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
)

type SubmitFunc func(context.Context, []*model.TensorNetworkFlow) error

type Submitter struct {
	submitInterval time.Duration
	flowChan       chan *model.TensorNetworkFlow
	submitFunc     SubmitFunc
	Palace         palace.Palace
	LearnHandler   *Learn
	ClusterName    string
}

func NewSubmitter(
	clusterManager *k8s.ClusterInfoManager,
	intv time.Duration,
	submitFunc SubmitFunc) *Submitter {
	Palace, err := palace.Init()
	if err != nil {
		logging.GetLogger().Error().Msgf("init palace failed, %+v.", err)
		return nil
	}
	lh := NewLearn(clusterManager)
	clusterName, ok := clusterManager.ClusterName()
	if !ok {
		clusterName = "default"
	}

	s := &Submitter{
		submitInterval: intv,
		submitFunc:     submitFunc,
		flowChan:       make(chan *model.TensorNetworkFlow, 50),
		Palace:         Palace,
		LearnHandler:   lh,
		ClusterName:    clusterName,
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

		// start learn
		go func() {
			err := s.LearnHandler.ListenConfigMap(context.Background())
			if err != nil {
				logging.GetLogger().Error().Msgf("listen configmap error, %v", err)
			}
		}()

		timestamp := time.Duration(s.submitInterval.Seconds() + float64(rand.Intn(120)))
		ticker := time.NewTicker(timestamp * time.Second)
		defer ticker.Stop()
		behavioralLearnFlag := false
		if bl := os.Getenv("BL_ENABLED"); bl == "1" {
			behavioralLearnFlag = true
		}

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
					if behavioralLearnFlag {
						s.SendToBehavioralLearn(*flow)
					}

				} else {
					sflow.Increment += 1
					sflow.UpdatedAt = time.Now()
					if behavioralLearnFlag {
						go s.SendToBehavioralLearn(*flow)
					}
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
					// go s.SendToBehavioralLearnIncrement(*flow)
					//delete
					delete(flowMap, flow.UUID)
				}
			}
		}
	}()
}

func (s *Submitter) SendToBehavioralLearn(networkFlow model.TensorNetworkFlow) {
	timestamp := time.Now().Unix()
	logging.GetLogger().Debug().Msgf("send to behavioral learn, %+v", networkFlow)
	resourceUUID := util.GenerateUUID(networkFlow.SrcCluster, networkFlow.SrcNamespace, networkFlow.SrcKind, networkFlow.SrcOwnerName)
	behavioralLearn := model.BehavioralKafkaEvent{
		ResourceUUID:    resourceUUID,
		ContainerID:     networkFlow.SrcContainerID,
		EventType:       model.BehavioralLearnKafkaNetworkEvent,
		Port:            int(networkFlow.DstPort),
		ProcessName:     networkFlow.DstProcess,
		LearningStatus:  model.BehavioralLearningStatusEnabled,
		SourceResource:  fmt.Sprintf("%s/%s/%s(%s)", s.ClusterName, networkFlow.SrcNamespace, networkFlow.SrcOwnerName, networkFlow.SrcKind),
		DestResource:    fmt.Sprintf("%s/%s/%s(%s)", s.ClusterName, networkFlow.DstNamespace, networkFlow.DstOwnerName, networkFlow.DstKind),
		ClusterKey:      networkFlow.DstCluster,
		Namespace:       networkFlow.DstNamespace,
		Kind:            networkFlow.DstKind,
		ResourceName:    networkFlow.DstOwnerName,
		StreamDirection: 1,
		CreatedAt:       timestamp,
		ContainerName:   networkFlow.SrcContainerName,
	}
	retFlag := s.LearnHandler.NeedSendToBehavioralLearn(resourceUUID, networkFlow, 1)
	logging.GetLogger().Debug().Msgf("send to behavioral learn, %+v", retFlag)
	if retFlag.SendToBehavioralLearn {
		logging.GetLogger().Info().Msgf("send to behavioral learn, %+v", behavioralLearn)
		behavioralLearn.LearningStatus = retFlag.Status
		err := s.Palace.SendBehavioralLearn(behavioralLearn)
		if err != nil {
			logging.GetLogger().Err(err).Msg("send behavioral learn failed.")
		}
	}
	if retFlag.SendToAlert {
		err := s.LearnHandler.Alert.Send(&NetworkArg{
			ContainerID:     networkFlow.SrcContainerID,
			ContainerName:   networkFlow.SrcContainerName,
			ProcessName:     networkFlow.DstProcess,
			StreamDirection: "out",
			ClusterID:       networkFlow.SrcCluster,
			Cluster:         s.ClusterName,
			Namespace:       networkFlow.SrcNamespace,
			ResourceKind:    networkFlow.SrcKind,
			ResourceName:    networkFlow.SrcOwnerName,
			PodName:         networkFlow.SrcPodName,
			PodUID:          networkFlow.SrcPodUid,
			Port:            int(networkFlow.DstPort),
			Hostname:        "pod",
			SrcResource:     behavioralLearn.DestResource,
		})
		if err != nil {
			logging.GetLogger().Err(err).Msg("send alert failed.")
		}
	}

	// reverse
	resourceUUID = util.GenerateUUID(networkFlow.DstCluster, networkFlow.DstNamespace, networkFlow.DstKind, networkFlow.DstOwnerName)
	behavioralLearn = model.BehavioralKafkaEvent{
		ResourceUUID:    resourceUUID,
		ContainerID:     networkFlow.DstContainerID,
		EventType:       model.BehavioralLearnKafkaNetworkEvent,
		Port:            int(networkFlow.DstPort),
		ProcessName:     networkFlow.SrcProcess,
		LearningStatus:  model.BehavioralLearningStatusEnabled,
		SourceResource:  fmt.Sprintf("%s/%s/%s(%s)", s.ClusterName, networkFlow.DstNamespace, networkFlow.DstOwnerName, networkFlow.DstKind),
		DestResource:    fmt.Sprintf("%s/%s/%s(%s)", s.ClusterName, networkFlow.SrcNamespace, networkFlow.SrcOwnerName, networkFlow.SrcKind),
		ClusterKey:      networkFlow.SrcCluster,
		Namespace:       networkFlow.SrcNamespace,
		Kind:            networkFlow.SrcKind,
		ResourceName:    networkFlow.SrcOwnerName,
		StreamDirection: 2,
		CreatedAt:       timestamp,
		ContainerName:   networkFlow.DstContainerName,
	}

	tmpNetworkFlow := model.TensorNetworkFlow{
		SrcCluster:       networkFlow.DstCluster,
		SrcNamespace:     networkFlow.DstNamespace,
		SrcKind:          networkFlow.DstKind,
		SrcOwnerName:     networkFlow.DstOwnerName,
		SrcContainerName: networkFlow.DstContainerName,
		SrcContainerID:   networkFlow.DstContainerID,
		SrcProcess:       networkFlow.DstProcess,
		SrcPid:           networkFlow.DstPid,
		SrcPodName:       networkFlow.DstPodName,
		SrcPodUid:        networkFlow.DstPodUid,
		DstPort:          networkFlow.DstPort,
		DstCluster:       networkFlow.SrcCluster,
		DstNamespace:     networkFlow.SrcNamespace,
		DstKind:          networkFlow.SrcKind,
		DstOwnerName:     networkFlow.SrcOwnerName,
		DstContainerName: networkFlow.SrcContainerName,
		DstContainerID:   networkFlow.SrcContainerID,
		DstProcess:       networkFlow.SrcProcess,
	}
	retFlag = s.LearnHandler.NeedSendToBehavioralLearn(resourceUUID, tmpNetworkFlow, 2)
	logging.GetLogger().Debug().Msgf("send to behavioral learn, %+v", retFlag)
	if retFlag.SendToBehavioralLearn {
		logging.GetLogger().Debug().Msgf("send to behavioral learn, %+v", behavioralLearn)
		behavioralLearn.LearningStatus = retFlag.Status
		err := s.Palace.SendBehavioralLearn(behavioralLearn)
		if err != nil {
			logging.GetLogger().Err(err).Msg("send behavioral learn failed.")
		}
	}
	if retFlag.SendToAlert {
		err := s.LearnHandler.Alert.Send(&NetworkArg{
			ContainerID:     networkFlow.DstContainerID,
			ContainerName:   networkFlow.DstContainerName,
			ProcessName:     networkFlow.SrcProcess,
			StreamDirection: "in",
			ClusterID:       networkFlow.DstCluster,
			Cluster:         s.ClusterName,
			Namespace:       networkFlow.DstNamespace,
			ResourceKind:    networkFlow.DstKind,
			ResourceName:    networkFlow.DstOwnerName,
			PodName:         networkFlow.DstPodName,
			PodUID:          networkFlow.DstPodUid,
			Hostname:        "pod",
			SrcResource:     behavioralLearn.DestResource,
			Port:            int(networkFlow.DstPort),
		})
		if err != nil {
			logging.GetLogger().Err(err).Msg("send alert failed.")
		}
	}
}
