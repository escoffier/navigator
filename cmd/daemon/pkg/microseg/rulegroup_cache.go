package microseg

import (
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

// ruleGroupLister is the subset of the generated NetworkPolicyRuleGroupLister
// that RuleGroupController depends on. A *streamRuleCache implements it too,
// so RuleGroupController's Run/syncPolicy/ReSyncAllPolicy/checkSync logic
// (written against the k8s-informer lister) works unmodified against either
// transport.
type ruleGroupLister interface {
	List(selector labels.Selector) ([]*crdv1alpha1.NetworkPolicyRuleGroup, error)
	Get(name string) (*crdv1alpha1.NetworkPolicyRuleGroup, error)
}

// streamRuleCache holds the rule groups most recently pushed over gRPC by
// clustermanager, replacing the k8s informer cache as RuleGroupController's
// source of "current state".
type streamRuleCache struct {
	mu     sync.RWMutex
	byName map[string]*crdv1alpha1.NetworkPolicyRuleGroup
}

func newStreamRuleCache() *streamRuleCache {
	return &streamRuleCache{byName: make(map[string]*crdv1alpha1.NetworkPolicyRuleGroup)}
}

func (c *streamRuleCache) Set(rg *crdv1alpha1.NetworkPolicyRuleGroup) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byName[rg.Name] = rg
}

func (c *streamRuleCache) Delete(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byName, name)
}

func (c *streamRuleCache) Get(name string) (*crdv1alpha1.NetworkPolicyRuleGroup, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rg, ok := c.byName[name]
	if !ok {
		return nil, apierrors.NewNotFound(crdv1alpha1.Resource("networkpolicyrulegroup"), name)
	}
	return rg, nil
}

func (c *streamRuleCache) List(selector labels.Selector) ([]*crdv1alpha1.NetworkPolicyRuleGroup, error) {
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

// ReplaceAll atomically swaps the cache contents with a fresh bootstrap
// snapshot, returning the names that were present before but are absent from
// the new snapshot (the caller must enqueue these for deletion so state
// converges correctly after a reconnect).
func (c *streamRuleCache) ReplaceAll(all []*crdv1alpha1.NetworkPolicyRuleGroup) (removed []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	newMap := make(map[string]*crdv1alpha1.NetworkPolicyRuleGroup, len(all))
	for _, rg := range all {
		newMap[rg.Name] = rg
	}
	for name := range c.byName {
		if _, ok := newMap[name]; !ok {
			removed = append(removed, name)
		}
	}
	c.byName = newMap
	return removed
}
