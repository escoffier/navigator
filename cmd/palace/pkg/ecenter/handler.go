package ecenter

import (
	"context"
	"errors"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/pb"
)

var (
	ErrSendTimeout = errors.New("send timeout")
)

type EcHandler struct {
	concurrency int

	ecCli   pb.EventsCenterCollectionServiceClient
	uuidGen *uuid.Generator

	inputChan chan *outputs.Response
}

func NewEcHandler(bufferSize, concurrency int, ecCli pb.EventsCenterCollectionServiceClient) (*EcHandler, error) {
	uuidGen, err := uuid.NewGenerator()
	if err != nil {
		return nil, err
	}
	e := &EcHandler{
		concurrency: concurrency,
		uuidGen:     uuidGen,
		ecCli:       ecCli,
		inputChan:   make(chan *outputs.Response, bufferSize),
	}
	e.asyncLoop()
	return e, nil
}

func isLegalTag(tag string) bool {
	switch tag {
	case "Watson", "ATT&CK":
		return true
	default:
		return false
	}
}

func (e *EcHandler) Input(ctx context.Context, data *outputs.Response) error {
	select {
	case <-ctx.Done():
		return ErrSendTimeout
	case e.inputChan <- data:
		return nil
	}
}

func (e *EcHandler) handle(data *outputs.Response) error {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("Panic %v", r)
		}
	}()

	ruleCategory := "ATT&CK"
	if len(data.Tags) > 0 {
		for _, tag := range data.Tags {
			if isLegalTag(tag) {
				ruleCategory = tag
				break
			}
		}
	}
	ownerResName, ok := data.OutputFields[rtdetect.KeyOwnerResName]
	if ok {
		delete(data.OutputFields, rtdetect.KeyOwnerResName)
	}
	ownerResKind, ok := data.OutputFields[rtdetect.KeyOwnerResKind]
	if ok {
		delete(data.OutputFields, rtdetect.KeyOwnerResKind)
	}

	clusterKey, ok := data.OutputFields[rtdetect.KeyClusterKey]
	if ok {
		delete(data.OutputFields, rtdetect.KeyClusterKey)
	}

	var uuid uint64
	uuidStr, ok := data.OutputFields[rtdetect.KeyUuid]
	if ok {
		delete(data.OutputFields, rtdetect.KeyUuid)
		uuid, _ = strconv.ParseUint(uuidStr, 10, 64)
	}
	eventReq := rtdetect.GenerateAttackEvent(model.AlertModuleContainerSecurity, ruleCategory, e.uuidGen, data, clusterKey, uuid, func(namespace, podName string) (kind, name string, ok bool) {
		if podName == "" && namespace == "" {
			return "Node", data.Hostname, true
		} else if len(ownerResName) > 0 && len(ownerResKind) > 0 {
			return ownerResKind, ownerResName, true
		}
		return "", "", false
	})
	oneCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err := e.ecCli.SendNotification(oneCtx, eventReq)
	return err
}
func (e *EcHandler) asyncLoop() {
	for i := 0; i < e.concurrency; i++ {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("Panic %v", r)
				}
			}()

			for d := range e.inputChan {
				if err := e.handle(d); err != nil {
					logging.Get().Err(err).Msgf("handle error. data: %+v", d)
				}
			}
		}()
	}
}
