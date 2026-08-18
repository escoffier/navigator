package microseg

import (
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

// ruleGroupLister is the subset of the generated NetworkPolicyRuleGroupLister
// that syncPolicyRules/deleteRuleGroup depend on. A *pushedRuleGroupCache
// implements it too, so that code (unchanged by this migration) works against
// either transport.
type ruleGroupLister interface {
	List(selector labels.Selector) ([]*crdv1alpha1.NetworkPolicyRuleGroup, error)
	Get(name string) (*crdv1alpha1.NetworkPolicyRuleGroup, error)
}

// pushedRuleGroupCache tracks the NetworkPolicyRuleGroup objects most recently
// pushed to daemons over gRPC, replacing the round-trip through the k8s CRD +
// informer that syncPolicyRules used to rely on to know "what's out there now".
type pushedRuleGroupCache struct {
	mu     sync.RWMutex
	byName map[string]*crdv1alpha1.NetworkPolicyRuleGroup
}

func newPushedRuleGroupCache() *pushedRuleGroupCache {
	return &pushedRuleGroupCache{byName: make(map[string]*crdv1alpha1.NetworkPolicyRuleGroup)}
}

func (c *pushedRuleGroupCache) Set(rg *crdv1alpha1.NetworkPolicyRuleGroup) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byName[rg.Name] = rg
}

func (c *pushedRuleGroupCache) Delete(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byName, name)
}

func (c *pushedRuleGroupCache) Get(name string) (*crdv1alpha1.NetworkPolicyRuleGroup, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rg, ok := c.byName[name]
	if !ok {
		return nil, apierrors.NewNotFound(crdv1alpha1.Resource("networkpolicyrulegroup"), name)
	}
	return rg, nil
}

func (c *pushedRuleGroupCache) List(selector labels.Selector) ([]*crdv1alpha1.NetworkPolicyRuleGroup, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*crdv1alpha1.NetworkPolicyRuleGroup
	for _, rg := range c.byName {
		if selector == nil || selector.Matches(labels.Set(rg.Labels)) {
			out = append(out, rg)
		}
	}
	return out, nil
}

// ListForNode returns every rule group currently pushed for a given node,
// used to build the bootstrap snapshot when a daemon (re)connects (Task 10).
func (c *pushedRuleGroupCache) ListForNode(nodeName string) []*crdv1alpha1.NetworkPolicyRuleGroup {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*crdv1alpha1.NetworkPolicyRuleGroup
	for _, rg := range c.byName {
		if rg.Spec.NodeName == nodeName {
			out = append(out, rg)
		}
	}
	return out
}
