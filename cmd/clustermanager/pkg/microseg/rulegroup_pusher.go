package microseg

import (
	"context"
	stderrors "errors"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/clientset/versioned"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

// errNodeNotConnected marks a grpcRuleGroupPusher push failure that happened
// because the target node has no live daemon connection right now, as
// opposed to a genuine delivery/protocol error. reconcileAllPolicies uses
// errors.Is against this to treat that class of failure as non-blocking for
// its warm-gate decision: Create/Update already write pushedRuleGroupCache
// through before attempting delivery, and Delete deliberately keeps its
// stale entry on a failed push (see grpcRuleGroupPusher.Delete) — so the
// cache is already correct either way, and the node gets caught up the
// moment it connects (via RegisterOnConnect once warm, or immediately via
// markWarmAndSync's snapshot if it's already connected by then).
var errNodeNotConnected = stderrors.New("microseg: target node has no live daemon connection")

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
	// Now that syncPolicyRules returns (rather than swallows) this error,
	// a retried delete of an already-deleted rule group would otherwise
	// spuriously fail the whole policy sync — mirror DeleteByPolicy's
	// existing IsNotFound tolerance below.
	err := p.clientset.MicrosegmentationV1alpha1().NetworkPolicyRuleGroups().Delete(ctx, name, v1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	return nil
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
// ConnectedNodeKeys mirrors the method of the same name on
// ruleGroupOnConnectStream (networkpolicy_controller.go); the concrete
// rpcstream.MessageStream passed to NewNetworkPolicyController already
// implements it, satisfying both narrow interfaces with one object.
type ruleGroupStreamPusher interface {
	PushRuleGroup(ctx context.Context, nodeKey string, msgType pb.MessageType, req *pb.NetworkPolicyRuleGroupReq) error
	ConnectedNodeKeys() []string
}

// grpcRuleGroupPusher pushes rule-group changes over the daemon<->clustermanager
// gRPC stream and keeps pushedRuleGroupCache in sync so RegisterOnConnect (Task
// 10) can serve bootstrap snapshots. Used when MICROSEG_GRPC_ENABLED=true.
type grpcRuleGroupPusher struct {
	cache  *pushedRuleGroupCache
	stream ruleGroupStreamPusher
}

// wrapPushErr classifies a PushRuleGroup(Sync) failure: if nodeKey has no
// live connection right now, it's wrapped as errNodeNotConnected so callers
// (reconcileAllPolicies) can tell it apart from a genuine delivery failure
// to a node that IS connected. Returns nil unchanged.
func (p *grpcRuleGroupPusher) wrapPushErr(err error, nodeKey string) error {
	if err == nil {
		return nil
	}
	for _, connected := range p.stream.ConnectedNodeKeys() {
		if connected == nodeKey {
			return err
		}
	}
	return fmt.Errorf("%w: %s: %v", errNodeNotConnected, nodeKey, err)
}

func (p *grpcRuleGroupPusher) Create(ctx context.Context, rg *crdv1alpha1.NetworkPolicyRuleGroup) error {
	unlock := p.cache.LockNode(rg.Spec.NodeName)
	defer unlock()
	p.cache.Set(rg)
	req := &pb.NetworkPolicyRuleGroupReq{RuleGroup: ruleGroupToPayload(rg)}
	nodeKey := rg.Spec.NodeName + daemonNodeKeySuffix
	return p.wrapPushErr(p.stream.PushRuleGroup(ctx, nodeKey, pb.MessageType_CREATE, req), nodeKey)
}

func (p *grpcRuleGroupPusher) Update(ctx context.Context, _, desired *crdv1alpha1.NetworkPolicyRuleGroup) error {
	unlock := p.cache.LockNode(desired.Spec.NodeName)
	defer unlock()
	p.cache.Set(desired)
	req := &pb.NetworkPolicyRuleGroupReq{RuleGroup: ruleGroupToPayload(desired)}
	nodeKey := desired.Spec.NodeName + daemonNodeKeySuffix
	return p.wrapPushErr(p.stream.PushRuleGroup(ctx, nodeKey, pb.MessageType_UPDATE, req), nodeKey)
}

func (p *grpcRuleGroupPusher) Delete(ctx context.Context, name string) error {
	// Safe to read rg.Spec.NodeName before acquiring the node's lock: a rule
	// group's name always embeds its node (e.g. "<policy>-<node>", see
	// generateRules), so the node this Get returns can never change under
	// us before we lock it.
	rg, err := p.cache.Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	unlock := p.cache.LockNode(rg.Spec.NodeName)
	defer unlock()
	nodeKey := rg.Spec.NodeName + daemonNodeKeySuffix
	req := &pb.NetworkPolicyRuleGroupReq{RuleGroup: &pb.NetworkPolicyRuleGroupPayload{Name: name}}
	if err := p.wrapPushErr(p.stream.PushRuleGroup(ctx, nodeKey, pb.MessageType_DELETE, req), nodeKey); err != nil {
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
	// pushErr accumulates delete failures so every group is still attempted
	// even after an earlier one fails in this same call, matching
	// syncPolicyRules's delete loop (issue #5) rather than aborting and
	// leaving the remaining groups' stale pushedRuleGroupCache entries in
	// place, which could resurrect on a later daemon reconnect.
	var pushErr error
	for _, rg := range groups {
		if err := p.Delete(ctx, rg.Name); err != nil {
			pushErr = err
		}
	}
	return pushErr
}
