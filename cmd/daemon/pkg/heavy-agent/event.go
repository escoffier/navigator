package heavyagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
)

type EventProcessor struct {
	cli      *Client
	handlers map[string]Handler
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
	for {
		var data = make([]byte, 40960)
		logging.Get().Info().Msg("begine to read event data")
		nBytes, err := p.cli.GetConn().Read(data)
		if err != nil {
			logging.Get().Err(err).Msg("read evevnt data err")
			time.Sleep(time.Millisecond * 500)
			if errors.Is(err, io.EOF) {
				err = p.cli.ReConnect()
			}
			continue
		}
		logging.Get().Info().Str(moduleKey, moduleName).Msgf("received agent event: %v", string(data))
		if nBytes > 0 {
			func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()

				searchString := "}{"
				start := 0
				index := bytes.Index(data, []byte(searchString))
				if index < 0 {
					index = len(data) - 1
				}
				count := bytes.Count(data, []byte(searchString))

				for i := 0; i <= count; i++ {
					value := data[start : index+1]
					event := make(map[string]interface{})
					// event := AttackLogDetail{}
					err = json.Unmarshal(value, &event)
					if err != nil {
						logging.Get().Err(err).Msg("unmarshal event")
						return
					}
					evtType := event["type"].(string)
					p.handlers[evtType].Handle(ctx, event)
					if err != nil {
						logging.Get().Err(err).Msg("post agent event err")
					}

					start = index + 1
					index = bytes.Index(data[start:], []byte(searchString))

					if index < 0 {
						index = len(data) - 1
					} else {
						index = index + start
					}

					if start > index {
						break
					}
				}

			}()
		}
	}
}

func (p *EventProcessor) AddHandler(name string, hanHandler Handler) {
	p.handlers[name] = hanHandler
}

func NewEventProcessor(clusterManagerSvc string, cli *Client) *EventProcessor {
	return &EventProcessor{
		cli:      cli,
		handlers: make(map[string]Handler),
	}
}
