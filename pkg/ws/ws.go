package ws

import (
	"context"
	"errors"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
)

type Handler interface {
	// Init 初始化
	Init(ctx context.Context)
	// Dispatch 将前端来的任务发给handler处理
	Dispatch(ctx context.Context, wsm model.WSMessage, dataC chan model.WSMessage, quitC chan struct{}) error
	// Collect 回收handler的数据返给前端
	Collect(ctx context.Context) error

	Clear(ctx context.Context, clear model.Clear)
}

// handlers 注册
var handlers = map[string]Handler{
	//model.WSDomainEventCenter:   NewEventCenterHandler(),
	model.WSDomainBehaviorLearn: NewBehaviorLearnHandler(),
}

func Init(ctx context.Context) {
	var err error

	for _, handler := range handlers {
		handler.Init(ctx)
		err = handler.Collect(ctx)
		if err != nil {
			logging.Get().Error().Err(err).Type("handler", handler).Msg("ws handler collect fails")
		}
	}
}

func Dispatch(ctx context.Context, wsm model.WSMessage, dataC chan model.WSMessage, quitC chan struct{}) error {
	handler, ok := handlers[wsm.Domain]
	if !ok {
		return errors.New("invalid domain")
	}
	return handler.Dispatch(ctx, wsm, dataC, quitC)
}

func Clear(ctx context.Context, wsm model.WSMessage) {
	rid, ok1 := wsm.Data["resource_id"].(float64)
	_type, ok2 := wsm.Data["type"].(string)
	if ok1 && ok2 {
		clearM := model.Clear{
			Domain:     wsm.Domain,
			ResourceID: rid,
			Type:       _type,
			ConnID:     wsm.ID,
		}
		handler, ok := handlers[clearM.Domain]
		if !ok {
			return
		}
		handler.Clear(ctx, clearM)
	} else {
		//fmt.Println("clear not ok", ok1, ok2, wsm)
	}
}
