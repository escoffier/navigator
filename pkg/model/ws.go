package model

import (
	"fmt"

	"github.com/google/uuid"
)

// WSMessage
//
// 前->后
//	{
//	   "domain": "event_center",  // 业务领域domain
//	   "scene": "new_events_notify",  // 业务场景scene
//	   "type": "control",  // 消息类型 （目前只有 control）
//	   "command": "start",  // 控制命令
//	   "data": {  // 控制命令相关的数据，具体业务自己定义
//	       "anchor": "3454324325254234125214"
//	   },
//	   "frequency": 10000,  // 期望的数据频率，单位毫秒
//	   "timestamp": 1694623445885
//	}
// 后->前
//  {
//     "domain": "event_center",  // 业务领域domain
//     "scene": "new_events_notify",  // 业务场景scene
//     "type": "data",  // 消息类型 （目前只有 data）
//     "data": {  // 具体的业务数据，map格式
//         "count": 2
//     },
//     "timestamp": 1694623445885
//  }

type WSMessage struct {
	Domain    string                 `json:"domain"`
	Scene     string                 `json:"scene"`
	Type      string                 `json:"type"`
	Command   string                 `json:"command"`
	Data      map[string]interface{} `json:"data"`
	Frequency int                    `json:"frequency"`
	Timestamp int64                  `json:"timestamp"`

	Username string `json:"username"`
	ID       string `json:"id"`
}

type Clear struct {
	Domain     string
	ResourceID float64
	Type       string
	ConnID     string
}

const (
	WSDomainEventCenter   = "event_center"
	WSDomainBehaviorLearn = "behavioral_learn"
	WSDomainMicroseg      = "microseg"

	WSSceneNewEventsNotify       = "new_events_notify"
	WSSceneLearningInModelAction = "learning_in_model_action"
	WSSceneLearningStatus        = "learning_status"
	WSSceneBatchAddStatus        = "batch_add_status"

	WSTypeData      = "data"
	WSTypeControl   = "control"
	WSTypeHeartbeat = "heartbeat"

	WSCommandStart  = "start"
	WSCommandStop   = "stop"
	WSCommandChange = "change" // 如：行为学习的查询条件变化；事件中心红点通知锚点变化

	WSDispatchTopicEventCenter = "ws_dispatch_topic_event_center"
	WSCollectTopicEventCenter  = "ws_collect_topic_event_center"

	WSCollectGroupIDEventCenterPrefix = "ws_collect_group_event_center_%s"
)

func WSCollectGroupIDEventCenter() string {
	return fmt.Sprintf(WSCollectGroupIDEventCenterPrefix, uuid.NewString())
}
