package rtdetect

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	pb "gitlab.com/piccolo_su/vegeta/pkg/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
)

var (
	filteredOutRulesSet = map[string]struct{}{
		"file integrity management":          struct{}{},
		"command whitelist":                  struct{}{},
		"seccomp":                            struct{}{},
		"Falco internal: syscall event drop": struct{}{},
	}
)

type ClusterManager interface {
	ClusterKey() (string, bool)
}
type EcHandler struct {
	ecCli   pb.EventsCenterCollectionServiceClient
	cm      ClusterManager
	uuidGen *uuid.Generator
}

func NewEcHandler(clusterManager ClusterManager) (*EcHandler, error) {
	ech, err := echelper.NewGRPCClientFromEnv()
	if err != nil {
		return nil, err
	}

	uuidGen, err := uuid.NewGenerator()
	if err != nil {
		return nil, err
	}
	return &EcHandler{
		ecCli:   ech,
		cm:      clusterManager,
		uuidGen: uuidGen,
	}, nil
}

func (ec *EcHandler) Handle(ctx context.Context, events []eventItem) error {
	clusterKey, ok := ec.cm.ClusterKey()
	if !ok {
		clusterKey = "unknown"
	}
	for _, item := range events {
		eventReq := echelper.GenerateAttackEvent(ec.uuidGen, item.data, clusterKey)

		func() {
			oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()
			_, err := ec.ecCli.SendNotification(oneCtx, eventReq)
			if err != nil {
				logging.GetLogger().WithContext(oneCtx).Errorf(err, "send events center error. data: %+v", eventReq)
			} else {
				// TODO remove
				logging.GetLogger().WithContext(oneCtx).Infof("send ecenter: %+v", eventReq)
			}
		}()

	}
	return nil
}

func (ec *EcHandler) CheckTarget(ctx context.Context, event eventItem) bool {
	_, exist := filteredOutRulesSet[event.data.Rule]
	return !exist
}
