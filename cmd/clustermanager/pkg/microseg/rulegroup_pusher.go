package microseg

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/clientset/versioned"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

// ruleGroupPusher delivers rule-group changes to daemons; syncPolicyRules and
// deleteRuleGroup call it instead of the k8s clientset directly, so the same
// diff/control-flow logic works over either transport.
type ruleGroupPusher interface {
	Create(ctx context.Context, rg *crdv1alpha1.NetworkPolicyRuleGroup) error
	Update(ctx context.Context, cur, desired *crdv1alpha1.NetworkPolicyRuleGroup) error
	Delete(ctx context.Context, name string) error
	DeleteByPolicy(ctx context.Context, policyName string) error
}

// k8sRuleGroupPusher is today's behavior: write the CRD to the k8s apiserver.
// Used when MICROSEG_GRPC_ENABLED is unset.
type k8sRuleGroupPusher struct {
	clientset *versioned.Clientset
}

func (p *k8sRuleGroupPusher) Create(ctx context.Context, rg *crdv1alpha1.NetworkPolicyRuleGroup) error {
	_, err := p.clientset.MicrosegmentationV1alpha1().NetworkPolicyRuleGroups().Create(ctx, rg, v1.CreateOptions{})
	return err
}

func (p *k8sRuleGroupPusher) Update(ctx context.Context, cur, desired *crdv1alpha1.NetworkPolicyRuleGroup) error {
	newRule := cur.DeepCopy()
	newRule.Spec = desired.Spec
	_, err := p.clientset.MicrosegmentationV1alpha1().NetworkPolicyRuleGroups().Update(ctx, newRule, v1.UpdateOptions{})
	return err
}

func (p *k8sRuleGroupPusher) Delete(ctx context.Context, name string) error {
	return p.clientset.MicrosegmentationV1alpha1().NetworkPolicyRuleGroups().Delete(ctx, name, v1.DeleteOptions{})
}

func (p *k8sRuleGroupPusher) DeleteByPolicy(ctx context.Context, policyName string) error {
	err := p.clientset.MicrosegmentationV1alpha1().NetworkPolicyRuleGroups().DeleteCollection(ctx, v1.DeleteOptions{}, v1.ListOptions{
		LabelSelector: "kubernetes.io/networkpolicy-name=" + policyName,
	})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	return nil
}

// ruleGroupStreamPusher is the subset of rpcstream.MessageStreamClient this
// package needs — kept narrow so tests can fake it without a real stream.
type ruleGroupStreamPusher interface {
	PushRuleGroup(ctx context.Context, nodeKey string, msgType pb.MessageType, req *pb.NetworkPolicyRuleGroupReq) error
}

// grpcRuleGroupPusher pushes rule-group changes over the daemon<->clustermanager
// gRPC stream and keeps pushedRuleGroupCache in sync so RegisterOnConnect (Task
// 10) can serve bootstrap snapshots. Used when MICROSEG_GRPC_ENABLED=true.
type grpcRuleGroupPusher struct {
	cache  *pushedRuleGroupCache
	stream ruleGroupStreamPusher
}

func (p *grpcRuleGroupPusher) Create(ctx context.Context, rg *crdv1alpha1.NetworkPolicyRuleGroup) error {
	p.cache.Set(rg)
	req := &pb.NetworkPolicyRuleGroupReq{RuleGroup: ruleGroupToPayload(rg)}
	return p.stream.PushRuleGroup(ctx, rg.Spec.NodeName+daemonNodeKeySuffix, pb.MessageType_CREATE, req)
}

func (p *grpcRuleGroupPusher) Update(ctx context.Context, _, desired *crdv1alpha1.NetworkPolicyRuleGroup) error {
	p.cache.Set(desired)
	req := &pb.NetworkPolicyRuleGroupReq{RuleGroup: ruleGroupToPayload(desired)}
	return p.stream.PushRuleGroup(ctx, desired.Spec.NodeName+daemonNodeKeySuffix, pb.MessageType_UPDATE, req)
}

func (p *grpcRuleGroupPusher) Delete(ctx context.Context, name string) error {
	rg, err := p.cache.Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	req := &pb.NetworkPolicyRuleGroupReq{RuleGroup: &pb.NetworkPolicyRuleGroupPayload{Name: name}}
	if err := p.stream.PushRuleGroup(ctx, rg.Spec.NodeName+daemonNodeKeySuffix, pb.MessageType_DELETE, req); err != nil {
		return err
	}
	p.cache.Delete(name)
	return nil
}

func (p *grpcRuleGroupPusher) DeleteByPolicy(ctx context.Context, policyName string) error {
	groups, err := p.cache.List(labels.SelectorFromValidatedSet(map[string]string{"kubernetes.io/networkpolicy-name": policyName}))
	if err != nil {
		return err
	}
	for _, rg := range groups {
		if err := p.Delete(ctx, rg.Name); err != nil {
			return err
		}
	}
	return nil
}
