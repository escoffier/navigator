package rtdetect

import (
	"context"
	"errors"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/netflow/pkg/netflow"
	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
	"gitlab.com/security-rd/go-pkg/logging"
	pb "gitlab.com/security-rd/go-pkg/pb"
)

var (
	filteredOutRulesSet = map[string]struct{}{
		"File Integrity Management":          {},
		"Command whitelist":                  {},
		"Seccomp":                            {},
		"Falco internal: syscall event drop": {},
	}
)

type EcHandler struct {
	ecCli       pb.EventsCenterCollectionServiceClient
	uuidGen     *uuid.Generator
	nodeResInfo *netflow.NodeResourceInfo
}

func NewEcHandler(nodeResInfo *netflow.NodeResourceInfo) (*EcHandler, error) {
	if nodeResInfo == nil {
		return nil, errors.New("argument is nil")
	}
	ech, err := echelper.NewGRPCClientFromEnv()
	if err != nil {
		return nil, err
	}

	uuidGen, err := uuid.NewGenerator()
	if err != nil {
		return nil, err
	}
	return &EcHandler{
		ecCli:       ech,
		uuidGen:     uuidGen,
		nodeResInfo: nodeResInfo,
	}, nil
}

func (ec *EcHandler) Handle(ctx context.Context, events []eventItem) error {

	for _, item := range events {
		containerID := item.data.OutputFields[rtdetect.FieldContainerID]
		if _, exist := ec.nodeResInfo.FindContainerCacheData(containerID); exist {
			logging.Get().Info().Msgf("Filter out container creation post events. data: %v. ContainerID: %s", item.data, containerID)
			continue
		}

		ruleCategory := "ATT&CK"
		if len(item.data.Tags) > 0 {
			ruleCategory = item.data.Tags[0]
		}

		eventReq := rtdetect.GenerateAttackEvent(model.AlertModuleContainerSecurity, ruleCategory, ec.uuidGen, item.data, item.clusterKey, uint64(item.uuid))

		func() {
			oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()
			_, err := ec.ecCli.SendNotification(oneCtx, eventReq)
			if err != nil {
				logging.Get().WithContext(oneCtx).Errorf(err, "send events center error. data: %+v", eventReq)
			}
		}()

	}
	return nil
}

func (ec *EcHandler) CheckTarget(ctx context.Context, event eventItem) bool {
	_, exist := filteredOutRulesSet[event.data.Rule]
	return !exist
}
