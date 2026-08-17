package microseg

import (
	"context"
	"fmt"
	"time"

	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"

	heavyagent "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
)

const requestTimeout = 3 * time.Second

type Address struct {
	IP    string `json:"ip"`
	PodID uint64 `json:"pod_id,omitempty"`
}

type NodeRule struct {
	Priority    int
	Protocol    string
	Direction   string
	Action      string
	Ports       []crdv1alpha1.NetworkPolicyPort `json:"ports,omitempty"`
	ToAddresses []Address                       `json:"to_addresses,omitempty"`
	FromAddress []Address                       `json:"from_addresses,omitempty"`
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

type PolicyClient interface {
	AddPolicy(rule *PolicyRule) error
	DeletePolicy(rule *PolicyRule) error

	AddContainer(pid int, podID uint64) error
	DeleteContaier(pid int, podID uint64) error

	AddReConnectionCallback(cb heavyagent.ReConnectCB)
}

type policyClient struct {
	*heavyagent.ControlClient
}

var _ PolicyClient = (*policyClient)(nil)

func NewPolicyClient(cli *heavyagent.ControlClient) PolicyClient {
	return &policyClient{
		ControlClient: cli,
	}
}

func (cli *policyClient) AddPolicy(rule *PolicyRule) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := cli.AddPolicyRule(ctx, &pb.AddPolicyRuleRequest{
		PolicyName: rule.PolicyName,
		Rules:      toPolicyRuleSpecs(rule.Rules),
	})
	if err != nil {
		return err
	}
	if resp.GetStatus() != 0 {
		return fmt.Errorf("data plane err :%d", resp.GetStatus())
	}
	return nil
}

func (cli *policyClient) DeletePolicy(rule *PolicyRule) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := cli.DeletePolicyRule(ctx, &pb.DeletePolicyRuleRequest{PolicyName: rule.PolicyName})
	if err != nil {
		return err
	}
	if resp.GetStatus() != 0 {
		return fmt.Errorf("data plane err :%d", resp.GetStatus())
	}
	return nil
}

func (cli *policyClient) AddContainer(pid int, podID uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := cli.PodUp(ctx, &pb.PodUpRequest{Pid: int32(pid), PodId: podID})
	if err != nil {
		return err
	}
	if resp.GetStatus() != 0 {
		return fmt.Errorf("data plane err :%d", resp.GetStatus())
	}
	return nil
}

func (cli *policyClient) DeleteContaier(pid int, podID uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := cli.PodDown(ctx, &pb.PodDownRequest{PodId: podID})
	if err != nil {
		return err
	}
	if resp.GetStatus() != 0 {
		return fmt.Errorf("data plane err :%d", resp.GetStatus())
	}
	return nil
}
