package heavyagent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
)

const eventPrefix = "#%% pre"

const eventHeaderLen = 11

type EventProcessor struct {
	cli        *Client
	handlers   map[string]Handler
	headerBuf  [eventHeaderLen]byte
	getReadBuf func(size uint32) []byte
	readBuf    []byte // cache for default getReadBuf
}

type EventHeader struct {
	Prefix []byte
	Length uint32
}

type AttackLogDetail struct {
	Type           string `json:"type"`
	ClusterKey     string `json:"cluster_key"`
	Namespace      string `json:"namespace"`
	ResKind        string `json:"res_kind"`
	ResName        string `json:"res_name"`
	ServiceId      int64  `json:"service_id"`
	AppName        string `json:"app_name"`
	Id             string `json:"id,omitempty"`
	RuleId         int64  `json:"rule_id"`
	Action         string `json:"action"`
	RuleName       string `json:"rule_name"`
	AttackIp       string `json:"attack_ip,omitempty"`
	AttackType     string `json:"attack_type"`
	AttackedApp    string `json:"attacked_app"`
	AttackedUrl    string `json:"attacked_url"`
	AttackLoad     string `json:"attack_load"`
	AttackTime     int64  `json:"attack_time"`
	ReqPkg         string `json:"req_pkg,omitempty"`
	RspPkg         string `json:"rsp_pkg,omitempty"`
	RspContentType string `json:"rsp_content_type,omitempty"`
}

func (p *EventProcessor) Run() {
	logging.Get().Info().Msg("start process agent event")
	var buf []byte

	for {
		logging.Get().Debug().Msg("begine to read event data")
		var readPos int
		var data = make([]byte, 4096)
		nBytes, err := p.cli.GetConn().Read(data)
		if err != nil {
			logging.Get().Err(err).Msg("read evevnt data err")
			time.Sleep(time.Millisecond * 500)
			if errors.Is(err, io.EOF) {
				err = p.cli.ReConnect()
			}
			continue
		}
		var message []byte
		if len(buf) > 0 {
			message = append(message, buf...)
			message = append(message, data...)
			buf = buf[:0]
		} else {
			message = append(message, data...)
		}
		logging.Get().Info().Str(moduleKey, moduleName).Msgf("received agent event: %v, length: %d", string(message[readPos:readPos+7]), nBytes)
		if nBytes > 0 {
			func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				for {
					if nBytes < readPos+7 {
						// cache buf
						// buf = slices.Concat(buf, message)
						logging.Get().Info().Msgf("cache len: %d", len(buf))
						buf = append(buf, message...)
						// currentPos = currentPos + nBytes
						break
					}
					pre := string(message[readPos : readPos+7])
					// logging.Get().Info().Str(moduleKey, moduleName).Msgf("readPos: %d, prefix: %v", readPos, message[readPos:(readPos+7)])

					var msgLen int32
					if pre == eventPrefix {
						if nBytes < readPos+11 {
							buf = append(buf, message...)
							// buf = slices.Concat(message, data)
							readPos = 0
							break
						}

						l := binary.LittleEndian.Uint32(message[readPos+7 : readPos+11])
						msgLen = int32(l)
						logging.Get().Info().Msgf("msg len: %d", msgLen)
						if nBytes < int(msgLen) {
							// buf = slices.Concat(buf, message)
							buf = append(buf, message...)
							// currentPos = currentPos + nBytes
							readPos = 0
							break
						}
					} else {
						logging.Get().Debug().Msg("skip invalid message header")
						// skip invalid header
						readPos = readPos + 1
						nBytes = nBytes - 1
						continue
					}
					event := make(map[string]interface{})
					err = json.Unmarshal(message[readPos+11:readPos+int(msgLen)+11], &event)
					if err != nil {
						logging.Get().Err(err).Msgf("unmarshal event, len : %d, value : %s", len(message), message[readPos+11:readPos+int(msgLen)+11])
						return
					}
					evtType := event["type"].(string)
					logging.Get().Info().Msgf("log event type: %s", evtType)
					err = p.handlers[evtType].Handle(ctx, event)
					if err != nil {
						logging.Get().Err(err).Msg("post agent event err")
					}
					if nBytes > int(msgLen)+11 {
						// move readPos to the next msg header
						readPos = readPos + int(msgLen) + 11
						nBytes = nBytes - int(msgLen) - 11
						continue
					} else {
						// here: msgLen == nBytes
						readPos = 0
						break
					}
				}
			}()
		}
	}
}

func (p *EventProcessor) readHeader() (EventHeader, error) {
	_, err := io.ReadFull(p.cli.GetConn(), p.headerBuf[:])
	if err != nil {
		return EventHeader{}, err
	}
	return EventHeader{
		Prefix: p.headerBuf[:7],
		Length: binary.LittleEndian.Uint32(p.headerBuf[7:11]),
	}, nil
}

func (p *EventProcessor) handlerError(err error) {
	logging.Get().Err(err).Msg("read evevnt data err")
	time.Sleep(time.Millisecond * 500)
	if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "use of closed network connection") {
		err = p.cli.ReConnect()
		if err != nil {
			logging.Get().Err(err).Msg("reconnect to uds server")
		}
	}
}

func (p *EventProcessor) Run1() {
	for {
		logging.Get().Debug().Msg("begine to read event data")
		header, err := p.readHeader()
		if err != nil {
			p.handlerError(err)
			continue
		}
		logging.Get().Debug().Msgf("header: %+v", header)

		paylaod := p.getReadBuf(header.Length)

		_, err = io.ReadFull(p.cli.GetConn(), paylaod)
		if err != nil {
			p.handlerError(err)
			continue
		}

		event := make(map[string]interface{})
		err = json.Unmarshal(paylaod, &event)
		if err != nil {
			logging.Get().Err(err).Msgf("unmarshal event, len : %d, value : %s", len(paylaod), paylaod)
			return
		}
		evtType := event["type"].(string)
		//logging.Get().Info().Msgf("log event type: %s", evtType)
		err = p.handlers[evtType].Handle(context.TODO(), event)
		if err != nil {
			logging.Get().Err(err).Msg("post agent event err")
		}
	}
}

func (p *EventProcessor) AddHandler(name string, hanHandler Handler) {
	p.handlers[name] = hanHandler
}

func NewEventProcessor(clusterManagerSvc string, cli *Client) *EventProcessor {
	p := &EventProcessor{
		cli:      cli,
		handlers: make(map[string]Handler),
	}
	p.getReadBuf = func(size uint32) []byte {
		if cap(p.readBuf) >= int(size) {
			return p.readBuf[:size]
		}
		p.readBuf = make([]byte, size)
		return p.readBuf
	}
	return p
}
