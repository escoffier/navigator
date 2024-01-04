package microseg

import (
	"encoding/json"
	"fmt"
	"net"

	heavyagent "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

type Address struct {
	IP    string `json:"ip"`
	PodID uint64 `json:"pod_id,omitempty"`
}

type NodeRule struct {
	Priority    int                             `json:"priority,omitempty"`
	Protocol    string                          `json:"prtocol,omitempty"`
	Direction   string                          `json:"direction,omitempty"`
	Action      string                          `json:"action"`
	Ports       []crdv1alpha1.NetworkPolicyPort `json:"ports,omitempty"`
	ToAddresses []Address                       `json:"toAddresses,omitempty"`
	FromAddress []Address                       `json:"fromAddress,omitempty"`
	Http        []*crdv1alpha1.Http             `json:"http,omitempty"`
}

type PolicyRule struct {
	MessageType int        `json:"msg_type"`
	PolicyName  string     `json:"policy_name"`
	Rules       []NodeRule `json:"rules,omitempty"`
}

type ContainerInfo struct {
	MessageType int    `json:"msg_type"`
	Pid         int    `json:"pid"`
	PodID       uint64 `json:"pod_id"`
}

type Response struct {
	Status int
}

type PolicyClient interface {
	AddPolicy(rule *PolicyRule) error
	DeletePolicy(rule *PolicyRule) error

	AddContainer(pid int, podID uint64) error
	DeleteContaier(pid int, podID uint64) error

	GetConn() net.Conn
	ReConnect() error
	Stop()
	SetController(controller *RuleGroupController)
	AddConnectionCallback(cb heavyagent.ReConnectCB)
}

type policyCliet struct {
	*heavyagent.Client
	controller *RuleGroupController
}

var _ PolicyClient = (*policyCliet)(nil)

func NewPolicyClient(cli *heavyagent.Client) PolicyClient {
	return &policyCliet{
		Client: cli,
	}
}

func (cli *policyCliet) AddPolicy(rule *PolicyRule) error {
	resp, err := cli.sendMessage(rule)
	if err != nil {
		return err
	}
	log.Debug().Msgf("policy reponse: %v", resp)
	if resp.Status != 0 {
		return fmt.Errorf("data plane err :%d", resp.Status)
	}
	return nil
}

func (cli *policyCliet) DeletePolicy(rule *PolicyRule) error {
	resp, err := cli.sendMessage(rule)
	if err != nil {
		return err
	}
	log.Debug().Msgf("policy reponse: %v", resp)
	if resp.Status != 0 {
		return fmt.Errorf("data plane err :%d", resp.Status)
	}
	return nil
}

func (cli *policyCliet) sendMessage(msg interface{}) (*Response, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	err = cli.Send(data)
	if err != nil {
		return nil, err
	}

	resp, err := cli.receiveResponse()
	return resp, err
}

func (cli *policyCliet) receiveResponse() (*Response, error) {
	var resp = &Response{}
	data, err := cli.Receive()
	if err != nil {
		return nil, err
	}
	log.Debug().Msgf("received %d bytes response", len(data))
	if len(data) > 0 {
		log.Debug().Msgf("response: %s", string(data))
		err = json.Unmarshal(data, resp)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func (cli *policyCliet) AddContainer(pid int, podID uint64) error {
	conInfo := &ContainerInfo{
		MessageType: 1,
		Pid:         pid,
		PodID:       podID,
	}

	resp, err := cli.sendMessage(conInfo)
	if err != nil {
		return err
	}
	if resp.Status != 0 {
		return fmt.Errorf("data plane err :%d", resp.Status)
	}
	return err
}
func (cli *policyCliet) DeleteContaier(pid int, podID uint64) error {
	conInfo := &ContainerInfo{
		MessageType: 2,
		Pid:         pid,
		PodID:       podID,
	}
	resp, err := cli.sendMessage(conInfo)
	if err != nil {
		return err
	}
	if resp.Status != 0 {
		return fmt.Errorf("data plane err :%d", resp.Status)
	}
	return err
}

func (cli *policyCliet) SetController(controller *RuleGroupController) {
	cli.controller = controller
	cli.AddReConnectCallback(func() {
		controller.ReSyncAllPolicy()
	})
}

func (cli *policyCliet) AddConnectionCallback(cb heavyagent.ReConnectCB) {
	cli.AddReConnectCallback(cb)
}
