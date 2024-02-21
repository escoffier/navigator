package ws

//
//import (
//	"context"
//	"encoding/json"
//	"math/rand"
//	"sync"
//	"time"
//
//	"gitlab.com/piccolo_su/vegeta/pkg/model"
//	"gitlab.com/security-rd/go-pkg/logging"
//	"gitlab.com/security-rd/go-pkg/mq"
//)
//
//type EventCenterHandler struct{}
//
//type query struct {
//	ID    string                 `json:"id"`
//	Type  string                 `json:"type"`
//	Param map[string]interface{} `json:"param"`
//}
//
//type result struct {
//	ID   string                 `json:"id"`
//	Type string                 `json:"type"`
//	Data map[string]interface{} `json:"data"`
//}
//
//var ecOnce sync.Once
//var mqWriter mq.Writer
//var mqReader mq.Reader
//
//type ecCollect struct {
//	lock         sync.Mutex
//	ecCollectMap map[string]chan model.WSMessage
//}
//
//func (ecc *ecCollect) Set(k string, v chan model.WSMessage) {
//	ecc.lock.Lock()
//	defer ecc.lock.Unlock()
//	ecc.ecCollectMap[k] = v
//}
//
//func (ecc *ecCollect) Get(k string) (chan model.WSMessage, bool) {
//	ecc.lock.Lock()
//	defer ecc.lock.Unlock()
//	v, ok := ecc.ecCollectMap[k]
//	return v, ok
//}
//
//var eccMap ecCollect
//
//// fixme
//var count int
//
//func NewEventCenterHandler() Handler {
//	return &EventCenterHandler{}
//}
//
//func (h *EventCenterHandler) Init(ctx context.Context) {
//	ecOnce.Do(func() {
//		var err error
//		mqFactory := mq.GetClientFactory()
//		mqWriter, err = mqFactory.Writer(ctx)
//		if err != nil {
//			logging.Get().Panic().Err(err).Msg("mq writer init fails!")
//		}
//
//		mqReader, err = mqFactory.Reader(ctx)
//		if err != nil {
//			logging.Get().Panic().Err(err).Msg("mq reader init fails!")
//		}
//
//		eccMap = ecCollect{
//			lock:         sync.Mutex{},
//			ecCollectMap: make(map[string]chan model.WSMessage),
//		}
//	})
//}
//
//func (h *EventCenterHandler) Dispatch(ctx context.Context, wsm model.WSMessage, ch chan model.WSMessage) error {
//
//	q := query{ID: wsm.ID}
//	switch wsm.Scene {
//	case model.WSSceneNewEventsNotify:
//		q.Type = "count_from_anchor"
//		q.Param = wsm.Data
//	}
//
//	_, err := json.Marshal(q)
//	if err != nil {
//		logging.Get().Error().Err(err).Msg("marshal query fails")
//		return err
//	}
//
//	eccMap.Set(wsm.ID, ch)
//
//	go func() {
//		for {
//			time.Sleep(time.Second * time.Duration(rand.Intn(10)+5))
//			count += rand.Intn(20)
//			ch <- model.WSMessage{
//				Domain:    wsm.Domain,
//				Scene:     wsm.Scene,
//				Type:      model.WSTypeData,
//				Data:      map[string]interface{}{"count": count, "anchor": ""},
//				Timestamp: time.Now().UnixMilli(),
//				ID:        wsm.ID,
//			}
//		}
//	}()
//
//	//return mqWriter.Write(ctx, model.WSDispatchTopicEventCenter, kafka.Message{
//	//	Topic: model.WSDispatchTopicEventCenter,
//	//	Value: bq,
//	//})
//	return nil
//}
//
//func (h *EventCenterHandler) Collect(ctx context.Context) error {
//	//err := mqReader.Subscribe(model.WSCollectTopicEventCenter, model.WSCollectGroupIDEventCenter(), func(ctx context.Context, message kafka.Message) error {
//	//	res := result{}
//	//	err := json.Unmarshal(message.Value, &res)
//	//	if err != nil {
//	//		logging.Get().Error().Err(err).Msg("Unmarshal result fails")
//	//		return err
//	//	}
//	//
//	//	ch, ok := eccMap[res.ID]
//	//	if !ok {
//	//		logging.Get().Error().Interface("result", res).Msg("no such collect chan")
//	//		return errors.New("no such collect chan")
//	//	}
//	//	ch <- model.WSMessage{
//	//		Domain:    model.WSDomainEventCenter,
//	//		Scene:     res.Type,
//	//		Type:      model.WSTypeData,
//	//		Data:      res.Data,
//	//		Timestamp: time.Now().UnixMilli(),
//	//		ID:        res.ID,
//	//	}
//	//	return nil
//	//})
//	//if err != nil {
//	//	logging.Get().Error().Err(err).Str("topic", model.WSCollectTopicEventCenter).Msg("mq reader subscribe fails!")
//	//	return err
//	//}
//	return nil
//}
