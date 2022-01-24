package rtdetect

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
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
	ecCli        pb.EventsCenterCollectionServiceClient
	uuidGen      *uuid.Generator
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
		ecCli:        ech,
		uuidGen:      uuidGen,
	}, nil
}

func (ec *EcHandler) Handle(ctx context.Context, events []eventItem) error {
	for _, item := range events {
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
				logging.GetLogger().WithContext(oneCtx).Errorf(err, "send events center error. data: %+v", eventReq)
			}
		}()

	}
	return nil
}

func (ec *EcHandler) CheckTarget(ctx context.Context, event eventItem) bool {
	_, exist := filteredOutRulesSet[event.data.Rule]
	return !exist
}
