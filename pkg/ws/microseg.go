package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/cache"
	"gitlab.com/security-rd/go-pkg/logging"
)

type Microseg struct {
	// Tasks    map[string]TaskChan
	watchers map[string]*StatusWatcher
	redis    *redis.Client
}

type TaskChan struct {
	dataChan chan model.WSMessage
	quitChan chan struct{}
	stopChan chan struct{}
	taskID   string
	redisSub *redis.PubSub
}

type TaskStatus struct {
	Phase      string   `json:"phase"`
	Success    int      `json:"success"`
	Failed     int      `json:"failed"`
	FailedId   []string `json:"failed_id"`
	Percentage int      `json:"percentage"`
	Total      int      `json:"total"`
}

var _ Handler = (*Microseg)(nil)

type StatusWatcher struct {
	Tasks map[string]*TaskChan
	redis *redis.Client
}

func NewMicrosegHanlder() *Microseg {
	return &Microseg{
		// Tasks:    map[string]TaskChan{},
		watchers: make(map[string]*StatusWatcher),
	}
}

// Clear implements Handler.
func (m *Microseg) Clear(ctx context.Context, clear model.Clear) {
	logging.Get().Info().Msgf("clear %v", clear)
	if w, ok := m.watchers[clear.ConnID]; ok {
		w.stopWatchAll()
		// for _, t := range w.Tasks {
		// 	// t.stopChan <- struct{}{}
		// 	logging.Get().Info().Msgf("stop task %s", t.taskID)
		// 	// delete(w.Tasks, k)
		// }
		delete(m.watchers, clear.ConnID)
	}
	// for k, t := range m.Tasks {
	// 	t.stopChan <- struct{}{}
	// 	delete(m.Tasks, k)
	// }
}

// Collect implements Handler.
func (m *Microseg) Collect(ctx context.Context) error {
	return nil
}

func (m *StatusWatcher) stopWatch(taskID string) error {
	if _, ok := m.Tasks[taskID]; ok {
		return m.Tasks[taskID].redisSub.Close()
	}
	return nil
}

func (m *StatusWatcher) stopWatchAll() error {
	var err error
	for _, t := range m.Tasks {
		err = t.redisSub.Close()
		logging.Get().Info().Msgf("close task %s", t.taskID)
		if err != nil {
			logging.Get().Err(err).Msgf("close task %s", t.taskID)
		}
	}
	return err
}

func (m *StatusWatcher) watchStatus(taskID string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	pubsub := m.redis.Subscribe(ctx, taskID)
	_, err := pubsub.Receive(ctx)
	if err != nil {
		logging.Get().Err(err).Msg("receive data")
		return
	}
	m.Tasks[taskID].redisSub = pubsub

	statusChan := pubsub.Channel()

	func() {
		for status := range statusChan {
			logging.Get().Info().Msgf("channel %s, status %s", status.Channel, status.Payload)
			var taskStatus TaskStatus
			err = json.Unmarshal([]byte(status.Payload), &taskStatus)
			if err != nil {
				logging.Get().Err(err).Msg("unmarshal task status")
			}
			m.Tasks[taskID].dataChan <- model.WSMessage{
				Domain:    model.WSDomainMicroseg,
				Scene:     model.WSSceneBatchAddStatus,
				Type:      model.WSTypeData,
				Data:      map[string]interface{}{"percentage": taskStatus.Percentage, "success": taskStatus.Success, "failed": taskStatus.Failed, "failed_id": taskStatus.FailedId, "total": taskStatus.Total},
				Timestamp: time.Now().UnixMicro(),
			}
			if taskStatus.Phase == "finished" {
				logging.Get().Info().Msgf("finish watch task %s status", taskID)
				pubsub.Close()
				return
			}
		}
	}()

	// <-stopChan
	// logging.Get().Info().Msgf("stop watch task %s status", taskID)
	// pubsub.Close()

	// for {
	// 	select {
	// 	case status := <-statusChan:
	// 		logging.Get().Info().Msgf("channel %s, status %s", status.Channel, status.Payload)
	// 		var taskStatus TaskStatus
	// 		err = json.Unmarshal([]byte(status.Payload), &taskStatus)
	// 		if err != nil {
	// 			logging.Get().Err(err).Msg("unmarshal task status")
	// 		}
	// 		m.Tasks[taskID].dataChan <- model.WSMessage{
	// 			Domain:    model.WSDomainMicroseg,
	// 			Scene:     model.WSSceneBatchAddStatus,
	// 			Type:      model.WSTypeData,
	// 			Data:      map[string]interface{}{"percentage": taskStatus.Percentage},
	// 			Timestamp: time.Now().UnixMicro(),
	// 		}
	// 		if taskStatus.Phase == "finished" {
	// 			logging.Get().Info().Msgf("finish watch task %s status", taskID)
	// 			pubsub.Close()
	// 			return
	// 		}
	// 	case <-stopChan:
	// 		logging.Get().Info().Msgf("stop watch task %s status", taskID)
	// 		return
	// 	}
	// }
}

func (m *StatusWatcher) watchStatus1(taskID string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	id := "0"
	for {
		readArgs := &redis.XReadArgs{
			Streams: []string{taskID, id},
			Block:   0,
		}
		dataStream, err := m.redis.XRead(ctx, readArgs).Result()
		if err != nil {
			logging.Get().Err(err).Msg("receive data")
		}

		for _, data := range dataStream {
			for _, message := range data.Messages {
				logging.Get().Info().Msgf("channel %s, status %v", message.ID, message.Values)

				playload := message.Values["data"]
				if playload == nil {
					continue
				}

				var taskStatus TaskStatus
				err = json.Unmarshal([]byte(playload.(string)), &taskStatus)
				if err != nil {
					logging.Get().Err(err).Msg("unmarshal task status")
				}
				m.Tasks[taskID].dataChan <- model.WSMessage{
					Domain:    model.WSDomainMicroseg,
					Scene:     model.WSSceneBatchAddStatus,
					Type:      model.WSTypeData,
					Data:      map[string]interface{}{"percentage": taskStatus.Percentage, "success": taskStatus.Success, "failed": taskStatus.Failed, "failed_id": taskStatus.FailedId, "total": taskStatus.Total},
					Timestamp: time.Now().UnixMicro(),
				}
				id = message.ID

				if taskStatus.Phase == "finished" {
					logging.Get().Info().Msgf("finish watch task %s status", taskID)
					// pubsub.Close()
					return
				}
			}
		}
	}
}

// Dispatch implements Handler.
func (m *Microseg) Dispatch(ctx context.Context, wsm model.WSMessage, dataC chan model.WSMessage, quitC chan struct{}) error {
	switch wsm.Scene {
	case model.WSSceneBatchAddStatus:
		if id, ok := wsm.Data["taskID"]; ok {
			logging.Get().Info().Msgf("connid: %s", wsm.ID)
			if _, ok := m.watchers[wsm.ID]; !ok {
				m.watchers[wsm.ID] = &StatusWatcher{
					Tasks: make(map[string]*TaskChan),
					redis: m.redis,
				}
			}
			if _, ok := m.watchers[wsm.ID].Tasks[id.(string)]; ok {
				logging.Get().Info().Msgf("duplicated task %s", id.(string))
				return fmt.Errorf("duplicated task %s", id.(string))
			}
			// stopChan := make(chan struct{})
			m.watchers[wsm.ID].Tasks[id.(string)] = &TaskChan{
				dataChan: dataC,
				quitChan: quitC,
				// stopChan: stopChan,
				taskID: id.(string),
			}

			// m.Tasks[id.(string)] = TaskChan{
			// 	dataChan: dataC,
			// 	quitChan: quitC,
			// 	stopChan: stopChan,
			// }
			go m.watchers[wsm.ID].watchStatus1(id.(string))
		}
	}
	return nil
}

// Init implements Handler.
func (m *Microseg) Init(ctx context.Context) {
	// m.Tasks = make(map[string]TaskChan)
	// m.watchers = make(map[string]*StatusWatcher)
	var err error
	m.redis, err = cache.NewRedis()
	if err != nil {
		logging.Get().Err(err).Msg("init microseg ws handler")
		return
	}
}
