package microseg

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
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

	// ToIPBlock   *IPBlock                        `json:"toIPBlock,omitempty"`
	// FromIPBlock *IPBlock                        `json:"fromIPBlock,omitempty"`
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
	Stop()
}

type policyCliet struct {
	conn          *net.UnixConn
	writeDeadline time.Time
	path          string
}

func NewPolicyClient(address string) (PolicyClient, error) {
	stats, err := os.Stat(address)
	if err != nil {
		return nil, fmt.Errorf("could not stat socket address(%s): %w", address, err)
	}

	switch stats.Mode() {
	case 0770, 1770:
		return nil, fmt.Errorf("socket address(%s) had incorrect mode(%v), must be 0770", address, stats.Mode())
	}

	conn, err := net.Dial("unix", address)
	if err != nil {
		return nil, fmt.Errorf("unable to dial socket(%s): %w", address, err)
	}
	return &policyCliet{conn: conn.(*net.UnixConn), path: address}, nil

}

func (cli *policyCliet) AddPolicy(rule *PolicyRule) error {
	// data, err := json.Marshal(rule)
	// if err != nil {
	// 	return err
	// }
	// cli.conn.SetWriteDeadline(cli.writeDeadline)
	// cli.writeDeadline = time.Time{}
	// _, err = cli.conn.Write(data)
	resp, err := cli.sendMessage(rule)
	if err != nil {
		return err
	}
	logging.Get().Info().Str("microseg", "policy-client").Msgf("policy reponse: %v", resp)
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
	logging.Get().Info().Str("microseg", "policy-client").Msgf("policy reponse: %v", resp)
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
	cli.conn.SetWriteDeadline(time.Now().Add(time.Second * 3))
	logging.Get().Info().Str("microseg", "client").Msgf("send data: %s", string(data))
	// cli.writeDeadline = time.Time{}
	_, err = cli.conn.Write(data)
	if err != nil {
		return nil, err
	}

	resp, err := cli.receiveResponse()
	return resp, err
}

func (cli *policyCliet) receiveResponse() (*Response, error) {
	var data = make([]byte, 4096)
	var resp = &Response{}
	nBytes, err := cli.conn.Read(data)
	if err != nil {
		return nil, err
	}
	logging.Get().Info().Str("microseg", "policy-client").Msgf("received %d bytes response", nBytes)
	if nBytes > 0 {
		logging.Get().Info().Msgf("response: %s", string(data))
		err = json.Unmarshal(data[:nBytes], resp)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func (cli *policyCliet) Stop() {
	cli.conn.Close()
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

func (cli *policyCliet) GetConn() net.Conn {
	return cli.conn
}
