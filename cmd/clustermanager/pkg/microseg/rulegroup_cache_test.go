package microseg

import (
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

func Test_pushedRuleGroupCache_SetGetDelete(t *testing.T) {
	c := newPushedRuleGroupCache()

	_, err := c.Get("a")
	if !apierrors.IsNotFound(err) {
		t.Fatalf("Get on empty cache: err = %v, want NotFound", err)
	}

	c.Set(&crdv1alpha1.NetworkPolicyRuleGroup{ObjectMeta: v1.ObjectMeta{Name: "a"}})
	got, err := c.Get("a")
	if err != nil || got.Name != "a" {
		t.Fatalf("Get(a) = %+v, %v", got, err)
	}

	c.Delete("a")
	if _, err := c.Get("a"); !apierrors.IsNotFound(err) {
		t.Fatalf("Get after Delete: err = %v, want NotFound", err)
	}
}

func Test_pushedRuleGroupCache_ListByLabel(t *testing.T) {
	c := newPushedRuleGroupCache()
	c.Set(&crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "a", Labels: map[string]string{"kubernetes.io/networkpolicy-name": "p1"}},
	})
	c.Set(&crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "b", Labels: map[string]string{"kubernetes.io/networkpolicy-name": "p2"}},
	})

	got, err := c.List(labels.SelectorFromValidatedSet(map[string]string{"kubernetes.io/networkpolicy-name": "p1"}))
	if err != nil || len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("List(p1) = %+v, %v, want [a]", got, err)
	}
}

func Test_pushedRuleGroupCache_ListForNode(t *testing.T) {
	c := newPushedRuleGroupCache()
	c.Set(&crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "a"},
		Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{NodeName: "node1"},
	})
	c.Set(&crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "b"},
		Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{NodeName: "node2"},
	})

	got := c.ListForNode("node1")
	if len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("ListForNode(node1) = %+v, want [a]", got)
	}
}

func Test_pushedRuleGroupCache_LockNode_SerializesSameNode(t *testing.T) {
	c := newPushedRuleGroupCache()
	unlockA := c.LockNode("node1")

	acquired := make(chan struct{})
	go func() {
		unlockB := c.LockNode("node1")
		close(acquired)
		unlockB()
	}()

	select {
	case <-acquired:
		t.Fatal("second LockNode(\"node1\") acquired while the first was still held")
	case <-time.After(100 * time.Millisecond):
	}

	unlockA()

	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("second LockNode(\"node1\") never acquired after the first unlocked")
	}
}

func Test_pushedRuleGroupCache_LockNode_DifferentNodesIndependent(t *testing.T) {
	c := newPushedRuleGroupCache()
	unlockA := c.LockNode("node1")
	defer unlockA()

	done := make(chan struct{})
	go func() {
		unlockB := c.LockNode("node2")
		unlockB()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("LockNode(\"node2\") was blocked by an unrelated LockNode(\"node1\") held by another goroutine")
	}
}
