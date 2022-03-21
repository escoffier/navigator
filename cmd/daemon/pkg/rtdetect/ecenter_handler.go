package rtdetect

import (
	"context"
	"errors"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
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
	ecCli      pb.EventsCenterCollectionServiceClient
	uuidGen    *uuid.Generator
	dockerInfo *nodeinfo.DockerInfoManager
	podResInfo *nodeinfo.PodResInfo
}

func NewEcHandler(dockerInfo *nodeinfo.DockerInfoManager, podResInfo *nodeinfo.PodResInfo) (*EcHandler, error) {
	if dockerInfo == nil {
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
		ecCli:      ech,
		uuidGen:    uuidGen,
		dockerInfo: dockerInfo,
		podResInfo: podResInfo,
	}, nil
}

func isLegalTag(tag string) bool {
	switch tag {
	case "Watson", "ATT&CK":
		return true
	default:
		return false
	}
}

func (ec *EcHandler) Handle(ctx context.Context, events []eventItem) error {
	for _, item := range events {
		if isEventItemWhitelisted(item.data, ec.dockerInfo) {
			logging.Get().Info().Msgf("Filter out container creation post events. data: %v.", item.data)
			continue
		}

		ruleCategory := "ATT&CK"
		if len(item.data.Tags) > 0 {
			for _, tag := range item.data.Tags {
				if isLegalTag(tag) {
					ruleCategory = tag
					break
				}
			}
		}

		eventReq := rtdetect.GenerateAttackEvent(model.AlertModuleContainerSecurity, ruleCategory, ec.uuidGen, item.data, item.clusterKey, uint64(item.uuid), func(namespace, podName string) (kind, name string, ok bool) {
			res, exist := ec.podResInfo.GetPod(namespace, podName)
			if exist {
				return res.Kind, res.Name, true
			}
			return "", "", false
		})

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
