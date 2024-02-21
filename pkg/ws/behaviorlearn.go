package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"gitlab.com/security-rd/go-pkg/logging"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	BehaviorLearnEventTypeAction = "action"
	BehaviorLearnEventTypeStatus = "status"
)

type BehaviorLearnHandler struct{}

type BehaviorEvent struct {
	Type         string `json:"type"`
	ResourceUUID uint32 `json:"resource_uuid"`
	model.BehavioralKafkaEvent
	BehavioralStatusEvent
}

type BehavioralStatusEvent struct {
	ResourceUUID uint32 `json:"resource_uuid"`
	Status       int    `json:"status"`
}

var BehaviorLearnCh = make(chan BehaviorEvent)

type ConnItem struct {
	connID    string
	_type     string
	condition map[string]interface{}
}

type chanS struct {
	dataC chan model.WSMessage
	quitC chan struct{}
}

type blCollect struct {
	lock                 sync.Mutex
	collectMap           map[string]chanS                       // conn -> wsm
	resourceConnItemsMap map[uint32]map[string]map[int]ConnItem // resource_id -> conn -> type -> condition
}

func (blc *blCollect) SetCM(k string, v chan model.WSMessage, q chan struct{}) {
	blc.lock.Lock()
	defer blc.lock.Unlock()
	blc.collectMap[k] = chanS{
		dataC: v,
		quitC: q,
	}
}

func (blc *blCollect) GetCM(k string) (chanS, bool) {
	blc.lock.Lock()
	defer blc.lock.Unlock()
	cs, ok := blc.collectMap[k]
	return cs, ok
}

func (blc *blCollect) DelCM(k string) {
	blc.lock.Lock()
	defer blc.lock.Unlock()
	delete(blc.collectMap, k)
}

func (blc *blCollect) SetRC(k uint32, v map[string]map[int]ConnItem) {
	blc.lock.Lock()
	defer blc.lock.Unlock()
	blc.resourceConnItemsMap[k] = v
}

func (blc *blCollect) AddRC(rid uint32, v ConnItem) {
	_, ok := blc.GetRC(rid)
	blc.lock.Lock()
	defer blc.lock.Unlock()
	// 一个链接：只同时监听一个资源
	for mrid, mv := range blc.resourceConnItemsMap {
		if _, ok := mv[v.connID]; ok && mrid != rid {
			delete(mv, v.connID)
		}
		blc.resourceConnItemsMap[mrid] = mv
	}

	if !ok {
		blc.resourceConnItemsMap[rid] = map[string]map[int]ConnItem{v.connID: {typeConvert(v._type): v}}
	} else {
		typeMaps, ok := blc.resourceConnItemsMap[rid][v.connID]
		if !ok {
			blc.resourceConnItemsMap[rid][v.connID] = map[int]ConnItem{typeConvert(v._type): v}
		}
		//blc.resourceConnItemsMap[rid][v.connID] = map[int]ConnItem{typeConvert(v._type): v}
		// 一个链接 + 一个资源：只同时监听一种事件action类型（外加状态类型）
		newTypeMaps := map[int]ConnItem{}
		statusChangeV, ok := typeMaps[model.BehavioralLearnStatusChangeEvent]
		if ok {
			newTypeMaps[model.BehavioralLearnStatusChangeEvent] = statusChangeV
		}
		newTypeMaps[typeConvert(v._type)] = v
		blc.resourceConnItemsMap[rid][v.connID] = newTypeMaps
	}
}

func typeConvert(t string) int {
	switch t {
	case model.BehavioralLearnKafkaFileEventStr:
		return model.BehavioralLearnKafkaFileEvent
	case model.BehavioralLearnKafkaCommandEventStr:
		return model.BehavioralLearnKafkaCommandEvent
	case model.BehavioralLearnKafkaNetworkEventStr:
		return model.BehavioralLearnKafkaNetworkEvent
	case model.BehavioralLearnStatusChangeEventStr:
		return model.BehavioralLearnStatusChangeEvent
	default:
		return 0
	}
}

func typeReverseConvert(t int) string {
	switch t {
	case model.BehavioralLearnKafkaFileEvent:
		return model.BehavioralLearnKafkaFileEventStr
	case model.BehavioralLearnKafkaCommandEvent:
		return model.BehavioralLearnKafkaCommandEventStr
	case model.BehavioralLearnKafkaNetworkEvent:
		return model.BehavioralLearnKafkaNetworkEventStr
	case model.BehavioralLearnStatusChangeEvent:
		return model.BehavioralLearnStatusChangeEventStr
	default:
		return ""
	}
}

func (blc *blCollect) DelRC(rid uint32, v ConnItem) bool {
	connEmpty := false
	_, ok := blc.GetRC(rid)
	blc.lock.Lock()
	defer blc.lock.Unlock()
	if ok {
		// 逐层清理
		_, ok := blc.resourceConnItemsMap[rid][v.connID]
		if ok {
			delete(blc.resourceConnItemsMap[rid][v.connID], typeConvert(v._type))
			if len(blc.resourceConnItemsMap[rid][v.connID]) == 0 {
				delete(blc.resourceConnItemsMap[rid], v.connID)
				connEmpty = true
				if len(blc.resourceConnItemsMap[rid]) == 0 {
					delete(blc.resourceConnItemsMap, rid)
				}
			}
		}
	}
	return connEmpty
}

func (blc *blCollect) setData(wsm model.WSMessage, _type string, dataC chan model.WSMessage, quitC chan struct{}) {
	blc.SetCM(wsm.ID, dataC, quitC)
	rid, ok1 := wsm.Data["resource_id"].(float64)
	if ok1 {
		blc.AddRC(uint32(rid), ConnItem{
			connID:    wsm.ID,
			_type:     _type,
			condition: wsm.Data,
		})
	}
}

func (blc *blCollect) clearData(rid float64, _type string, id string) {
	blc.delData(model.WSMessage{ID: id, Data: map[string]interface{}{"resource_id": rid, "type": _type}}, _type)
	blc.DelCM(id)
}

func (blc *blCollect) delData(wsm model.WSMessage, _type string) {
	rid, ok1 := wsm.Data["resource_id"].(float64)
	if ok1 {
		blc.DelRC(uint32(rid), ConnItem{
			connID: wsm.ID,
			_type:  _type,
		})
	}
}

func (blc *blCollect) GetRC(k uint32) (map[string]map[int]ConnItem, bool) {
	blc.lock.Lock()
	defer blc.lock.Unlock()
	v, ok := blc.resourceConnItemsMap[k]
	return v, ok
}

var blcMap blCollect

func NewBehaviorLearnHandler() Handler {
	return &BehaviorLearnHandler{}
}

func (h *BehaviorLearnHandler) Init(ctx context.Context) {
	blcMap = blCollect{
		lock:                 sync.Mutex{},
		collectMap:           make(map[string]chanS),
		resourceConnItemsMap: make(map[uint32]map[string]map[int]ConnItem),
	}
}

func (h *BehaviorLearnHandler) Dispatch(ctx context.Context, wsm model.WSMessage, dataC chan model.WSMessage, quitC chan struct{}) error {
	switch wsm.Scene {
	case model.WSSceneLearningInModelAction:
		_type, ok := wsm.Data["type"].(string)
		if !ok {
			return fmt.Errorf("invalid data type: %v", wsm.Data)
		}
		switch wsm.Command {
		case model.WSCommandStart, model.WSCommandChange:
			blcMap.setData(wsm, _type, dataC, quitC)
		case model.WSCommandStop:
			blcMap.delData(wsm, _type)
		}
	case model.WSSceneLearningStatus:
		switch wsm.Command {
		case model.WSCommandStart, model.WSCommandChange:
			blcMap.setData(wsm, model.BehavioralLearnStatusChangeEventStr, dataC, quitC)
		case model.WSCommandStop:
			blcMap.delData(wsm, model.BehavioralLearnStatusChangeEventStr)
		}
	}
	return nil
}

func (h *BehaviorLearnHandler) Clear(ctx context.Context, clear model.Clear) {
	blcMap.clearData(clear.ResourceID, clear.Type, clear.ConnID)
}

func (h *BehaviorLearnHandler) Collect(ctx context.Context) error {
	go func() {
		for {
			event, ok := <-BehaviorLearnCh
			if !ok {
				logging.Get().Error().Msg("BehaviorLearnCh closed?")
				break
			}
			cs, ok := blcMap.GetRC(event.ResourceUUID)
			if !ok {
				// 没有订阅这个resource的长链接，跳过
				continue
			}
			switch event.Type {
			case BehaviorLearnEventTypeAction:
				action := event.BehavioralKafkaEvent
				for cid, cItem := range cs {
					// 确认前端是否需要该类型的数据
					if cond, ok := cItem[action.EventType]; ok {
						// 过滤前端的查询条件
						if !filterCondition(action, cond) {
							continue
						}
						sendToChan(cid, action.ResourceUUID, model.WSSceneLearningInModelAction, map[string]interface{}{
							"resource_id": action.ResourceUUID,
							"type":        typeReverseConvert(action.EventType),
							"item":        fixAction(action),
						})
					}
				}
			case BehaviorLearnEventTypeStatus:
				status := event.BehavioralStatusEvent
				for cid, cItem := range cs {
					if _, ok := cItem[model.BehavioralLearnStatusChangeEvent]; ok {
						sendToChan(cid, status.ResourceUUID, model.WSSceneLearningStatus, map[string]interface{}{
							"resource_id": status.ResourceUUID,
							"status":      status.Status,
						})
					}
				}
			}
		}
	}()

	return nil
}

func SendToWS(event BehaviorEvent) {
	BehaviorLearnCh <- event
}

func sendToChan(cid string, resourceUUID uint32, scene string, data map[string]interface{}) {
	cs, ok := blcMap.GetCM(cid)
	if !ok {
		// 没有找到对应的链接，跳过（应该不会出现）
		logging.Get().Error().Uint32("ResourceUUID", resourceUUID).Str("conn_id", cid).Msg("no such collect chan")
		return
	}
	select {
	case <-cs.quitC:
		return
	default: // quit channel没有关闭的时候，才会走default
		select {
		case cs.dataC <- model.WSMessage{
			Domain:    model.WSDomainBehaviorLearn,
			Scene:     scene,
			Type:      model.WSTypeData,
			Data:      data,
			Timestamp: time.Now().UnixMicro(),
			ID:        cid,
		}:
			return
		}
	}
}

func filterCondition(action model.BehavioralKafkaEvent, cond ConnItem) bool {
	switch action.EventType {
	case model.BehavioralLearnKafkaFileEvent:
		return filterFileCondition(action, cond)
	case model.BehavioralLearnKafkaCommandEvent:
		return filterCommandCondition(action, cond)
	case model.BehavioralLearnKafkaNetworkEvent:
		return filterNetworkCondition(action, cond)
	}
	return false
}

func filterFileCondition(action model.BehavioralKafkaEvent, cond ConnItem) bool {
	searchStr, ok := cond.condition["search_str"].(string)
	if ok {
		if !strings.Contains(action.Name, searchStr) && !strings.Contains(action.Path, searchStr) {
			return false
		}
	}
	permission, ok := cond.condition["permission"].(int)
	if ok {
		if action.Permission != permission {
			return false
		}
	}

	hit := false
	allContainer, ok := cond.condition["all_container"].(bool)
	if ok {
		if !allContainer {
			cids, ok := cond.condition["cids"].([]interface{})
			if ok {
				for i := range cids {
					cidsis, ok := cids[i].(string)
					if !ok {
						continue
					}
					if action.ContainerID == cidsis {
						hit = true
						break
					}
				}
			}
		} else {
			hit = true
		}
	}

	return hit
}

func filterCommandCondition(action model.BehavioralKafkaEvent, cond ConnItem) bool {
	searchStr, ok := cond.condition["search_str"].(string)
	if ok {
		if !strings.Contains(action.Command, searchStr) && !strings.Contains(action.Path, searchStr) {
			return false
		}
	}
	hit := false
	allContainer, ok := cond.condition["all_container"].(bool)
	if ok {
		if !allContainer {
			cids, ok := cond.condition["cids"].([]interface{})
			if ok {
				for i := range cids {
					cidsis, ok := cids[i].(string)
					if !ok {
						continue
					}
					if action.ContainerID == cidsis {
						hit = true
						break
					}
				}
			}
		} else {
			hit = true
		}
	}

	return hit
}

func filterNetworkCondition(action model.BehavioralKafkaEvent, cond ConnItem) bool {
	streamDirection, ok := cond.condition["stream_direction"].(int)
	if ok {
		if action.StreamDirection != streamDirection {
			return false
		}
	}
	port, ok := cond.condition["port"].(string)
	if ok {
		if !strings.Contains(fmt.Sprintf("%d", action.Port), port) {
			return false
		}
	}

	searchStr, ok := cond.condition["search_str"].(string)
	if ok {
		if !strings.Contains(action.SourceResource, searchStr) && !strings.Contains(action.DestResource, searchStr) {
			return false
		}
	}

	hit := false
	allContainer, ok := cond.condition["all_container"].(bool)
	if ok {
		if !allContainer {
			cids, ok := cond.condition["cids"].([]interface{})
			if ok {
				for i := range cids {
					cidsis, ok := cids[i].(string)
					if !ok {
						continue
					}
					if action.ContainerID == cidsis {
						hit = true
						break
					}
				}
			}
		} else {
			hit = true
		}
	}

	return hit
}

func fixAction(action model.BehavioralKafkaEvent) map[string]interface{} {
	ma := make(map[string]interface{})
	ba, err := json.Marshal(action)
	if err != nil {
		logging.Get().Error().Err(err).Interface("action", action).Msg("marshal action fails")
		return ma
	}
	err = json.Unmarshal(ba, &ma)
	if err != nil {
		logging.Get().Error().Err(err).Interface("action", string(ba)).Msg("unmarshal action fails")
		return ma
	}
	ma["updated_at"] = action.CreatedAt
	ma["id"] = fmt.Sprintf("%d", action.SonyFlakeID)
	return ma
}
