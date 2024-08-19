package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/request"
	"gitlab.com/piccolo_su/vegeta/pkg/ws"
	"net/http"
	"sync"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/security-rd/go-pkg/logging"
)

type connData struct {
	ch       chan model.WSMessage
	quit     chan struct{}
	username string
	id       string

	lastMessage model.WSMessage
}

var upGrader = websocket.Upgrader{} // use default options
var connMap = make(map[*websocket.Conn]connData)

const (
	heartbeatInterval = 1000 * 30 // 30s
)

func (api *api) wsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var once = sync.Once{}
		logging.Get().Debug().Msg("ws start: " + time.Now().Format(time.RFC3339))
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		upGrader.CheckOrigin = func(r *http.Request) bool {
			return true
		}
		c, err := upGrader.Upgrade(w, r, nil)
		if err != nil {
			logging.Get().Error().Err(err).Msg("ws Upgrade err")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		logging.Get().Debug().Msg("ws Upgrade: " + time.Now().Format(time.RFC3339))

		username := request.GetUsernameFromContext(ctx)
		logging.Get().Debug().Msg("ws username: " + username + time.Now().Format(time.RFC3339))

		// 心跳控制
		heartbeatLastTime := time.Now().UnixMilli()

		// 断开控制
		c.SetCloseHandler(func(code int, text string) error {
			err = c.Close()
			if err != nil {
				logging.Get().Error().Err(err).Msg("ws close conn fails")
			}
			logging.Get().Debug().Msg("ws close conn success")
			return err
		})

		cdata := connData{
			ch:       make(chan model.WSMessage),
			quit:     make(chan struct{}),
			username: username,
			id:       uuid.NewString(),
		}
		connMap[c] = cdata
		quitCh := make(chan struct{})
		defer func() {
			// 清理数据结构
			ws.Clear(ctx, cdata.lastMessage)
			// 关闭发送给ws的通道
			close(cdata.quit)
			close(cdata.ch)
			// 关闭ws链接
			wsClose(&once, c)
			// 关闭退出通道
			close(quitCh)
		}()

		go func() {
			defer wsClose(&once, c)
			heartbeatChecker := time.NewTicker(heartbeatInterval * 2 * time.Millisecond)
			defer heartbeatChecker.Stop()
			for {
				select {
				// 心跳检查
				case <-heartbeatChecker.C:
					logging.Get().Debug().Msg("ws goroutine check heartbeat")
					if time.Now().UnixMilli()-heartbeatLastTime > heartbeatInterval*2 || heartbeatLastTime-time.Now().UnixMilli() > heartbeatInterval*2 {
						logging.Get().Error().Int64("heartbeatLastTime", heartbeatLastTime).Int64("now", time.Now().UnixMilli()).Err(err).Msg("ws heartbeat timeout")
						return
					}
				// 发送数据给client
				case data, ok := <-cdata.ch:
					logging.Get().Debug().Interface("data", data).Msg("ws send data")
					if !ok {
						logging.Get().Info().Msg("ws client ch closed")
						return
					}
					bd, err := json.Marshal(data)
					if err != nil {
						logging.Get().Error().Err(err).Interface("data", data).Msg("ws marshal fails")
						continue
					}
					err = c.WriteMessage(websocket.TextMessage, bd)
					if err != nil {
						logging.Get().Error().Err(err).Interface("data", data).Msg("ws write message fails")
						return
					}
				}
			}
		}()

		for {
			// 其他协程关闭conn，会导致这里产生err，并退出for循环
			logging.Get().Debug().Msg("ws read data waiting")
			mt, message, err := c.ReadMessage()
			if err != nil {
				logging.Get().Info().Err(err).Msg("ws read fails")
				break
			}
			logging.Get().Debug().Int("type", mt).Str("msg", string(message)).Msg("ws read data")

			wsm := model.WSMessage{}
			err = json.Unmarshal(message, &wsm)
			if err != nil {
				logging.Get().Info().Bytes("body", message).Err(err).Msg("ws message Unmarshal fails")
				break
			}

			// 更新心跳时间
			if wsm.Type == model.WSTypeHeartbeat {
				heartbeatLastTime = wsm.Timestamp
				continue
			}

			// 分发消息
			err = dispatch(ctx, mt, wsm, &cdata)
			if err != nil {
				logging.Get().Error().Err(err).Str("msg", string(message)).Msg("ws dispatch fails")
				break
			}
			logging.Get().Debug().Int("type", mt).Interface("msg", wsm).Msg("ws dispatch")
		}

		logging.Get().Debug().Err(err).Msg("ws quit")
	}
}

func dispatch(ctx context.Context, messageType int, wsm model.WSMessage, cdata *connData) error {
	if messageType != websocket.TextMessage {
		logging.Get().Error().Int("message type", messageType).Msg("invalid message type")
		return errors.New("invalid message type")
	}

	wsm.Username = cdata.username
	wsm.ID = cdata.id

	_, ok1 := wsm.Data["resource_id"].(float64)
	_, ok2 := wsm.Data["type"].(string)
	if ok1 && ok2 {
		cdata.lastMessage = wsm
	}

	return ws.Dispatch(ctx, wsm, cdata.ch, cdata.quit)
}

func wsClose(once *sync.Once, c *websocket.Conn) {
	once.Do(func() {
		err := c.CloseHandler()(websocket.CloseNoStatusReceived, "")
		if err != nil {
			logging.Get().Error().Err(err).Msg("ws close websocket conn fails")
			return
		}
	})
	logging.Get().Debug().Msg("ws close conn done")
}
