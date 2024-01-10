package microseg

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/google/uuid"
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

type MetaData struct {
	UUID string `json:"uuid"`
}
type PolicyRule struct {
	MetaData
	MessageType int        `json:"msg_type"`
	PolicyName  string     `json:"policy_name"`
	Rules       []NodeRule `json:"rules,omitempty"`
}

type ContainerInfo struct {
	MetaData
	MessageType int    `json:"msg_type"`
	Pid         int    `json:"pid"`
	PodID       uint64 `json:"pod_id"`
}

type Response struct {
	MetaData
	Status int `json:"status"`
}

type PolicyClient interface {
	AddPolicy(rule *PolicyRule) error
	DeletePolicy(rule *PolicyRule) error

	AddContainer(pid int, podID uint64) error
	DeleteContaier(pid int, podID uint64) error

	GetConn() net.Conn
	ReConnect() error
	Stop()
	// SetController(controller *RuleGroupController)
	AddReConnectionCallback(cb heavyagent.ReConnectCB)
}

type policyClient struct {
	*heavyagent.Client
}

var _ PolicyClient = (*policyClient)(nil)

func NewPolicyClient(cli *heavyagent.Client) PolicyClient {
	return &policyClient{
		Client: cli,
	}
}

func (cli *policyClient) AddPolicy(rule *PolicyRule) error {
	rule.MetaData.UUID = uuid.NewString()
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

func (cli *policyClient) DeletePolicy(rule *PolicyRule) error {
	rule.MetaData.UUID = uuid.NewString()
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

func (cli *policyClient) sendMessage(msg interface{}) (*Response, error) {
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

func (cli *policyClient) receiveResponse() (*Response, error) {
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

func (cli *policyClient) AddContainer(pid int, podID uint64) error {
	conInfo := &ContainerInfo{
		MessageType: 1,
		Pid:         pid,
		PodID:       podID,
		MetaData: MetaData{
			UUID: uuid.NewString(),
		},
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
func (cli *policyClient) DeleteContaier(pid int, podID uint64) error {
	conInfo := &ContainerInfo{
		MessageType: 2,
		Pid:         pid,
		PodID:       podID,
		MetaData: MetaData{
			UUID: uuid.NewString(),
		},
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

func (cli *policyClient) AddReConnectionCallback(cb heavyagent.ReConnectCB) {
	cli.AddConnectCallback(cb)
}
