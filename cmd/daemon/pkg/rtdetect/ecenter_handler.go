package rtdetect

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"

	pb "gitlab.com/tensorsecurity-rd/go-pkg/pb"
)

var (
	filteredOutRulesSet = map[string]struct{}{
		"file integrity management":          {},
		"command whitelist":                  {},
		"seccomp":                            {},
		"Falco internal: syscall event drop": {},
	}
)

type EcHandler struct {
	ecCli   pb.EventsCenterCollectionServiceClient
	uuidGen *uuid.Generator
}

func NewEcHandler() (*EcHandler, error) {
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
		uuidGen: uuidGen,
	}, nil
}

func (ec *EcHandler) Handle(ctx context.Context, events []eventItem) error {
	for _, item := range events {
		eventReq := rtdetect.GenerateAttackEvent(ec.uuidGen, item.data, item.clusterKey, item.uuid)

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
