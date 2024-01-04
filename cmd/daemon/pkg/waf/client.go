package waf

import (
	"encoding/json"

	heavyagent "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent"
	v1 "k8s.io/api/core/v1"
)

type Client interface {
	SendWafMessage(config *Config, pods []*v1.Pod) error
	DeleteWaf(pods []*v1.Pod) error
	SetController(controller *WafController)
}

type client struct {
	*heavyagent.Client
	controller *WafController
}
type Response struct {
	Status int
}

func NewWafClient(cli *heavyagent.Client) Client {
	return &client{
		Client: cli,
	}
}

func (cli *client) SendWafMessage(config *Config, pods []*v1.Pod) error {
	ips := make([]string, 0, len(pods))
	for _, po := range pods {
		if po.Status.PodIP != "" {
			ips = append(ips, po.Status.PodIP)
		}
	}
	if len(ips) == 0 {
		return nil
	}
	config.PodIPs = ips
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	cli.Send(data)
	if err != nil {
		return err
	}
	_, err = cli.receiveResponse()
	if err != nil {
		return err
	}

	return nil
}

func (cli *client) DeleteWaf(pods []*v1.Pod) error {
	type Message struct {
		MsgType int      `json:"msg_type"`
		PodIPs  []string `json:"pod_ips"`
	}

	msg := Message{
		MsgType: 8,
	}
	for _, po := range pods {
		if po.Status.PodIP != "" {
			msg.PodIPs = append(msg.PodIPs, po.Status.PodIP)
		}
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	cli.Send(data)
	if err != nil {
		return err
	}
	_, err = cli.receiveResponse()
	if err != nil {
		return err
	}

	return nil
}

func (cli *client) receiveResponse() (*Response, error) {
	data, err := cli.Receive()
	if err != nil {
		return nil, err
	}
	log.Debug().Str(moduleKey, moduleName).Msgf("received %d bytes response", len(data))
	var resp = &Response{}
	if len(data) > 0 {
		log.Debug().Str(moduleKey, moduleName).Msgf("response: %s", string(data))
		err = json.Unmarshal(data, resp)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func (cli *client) SetController(controller *WafController) {
	cli.controller = controller
	cli.AddReConnectCallback(func() {
		controller.TriggerAllSync()
	})
}
