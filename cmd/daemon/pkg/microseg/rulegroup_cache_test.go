package microseg

import (
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

func v1ObjectMeta(name string) v1.ObjectMeta {
	return v1.ObjectMeta{Name: name}
}

func Test_streamRuleCache_SetGetDelete(t *testing.T) {
	c := newStreamRuleCache()

	_, err := c.Get("a")
	if !apierrors.IsNotFound(err) {
		t.Fatalf("Get on empty cache: err = %v, want NotFound", err)
	}

	c.Set(&crdv1alpha1.NetworkPolicyRuleGroup{ObjectMeta: v1ObjectMeta("a")})
	got, err := c.Get("a")
	if err != nil || got.Name != "a" {
		t.Fatalf("Get(a) = %+v, %v", got, err)
	}

	c.Delete("a")
	_, err = c.Get("a")
	if !apierrors.IsNotFound(err) {
		t.Fatalf("Get after Delete: err = %v, want NotFound", err)
	}
}

func Test_streamRuleCache_List(t *testing.T) {
	c := newStreamRuleCache()
	c.Set(&crdv1alpha1.NetworkPolicyRuleGroup{ObjectMeta: v1ObjectMeta("a")})
	c.Set(&crdv1alpha1.NetworkPolicyRuleGroup{ObjectMeta: v1ObjectMeta("b")})

	all, err := c.List(labels.Everything())
	if err != nil || len(all) != 2 {
		t.Fatalf("List = %+v, %v, want 2 entries", all, err)
	}
}

func Test_streamRuleCache_ReplaceAll_ReturnsRemoved(t *testing.T) {
	c := newStreamRuleCache()
	c.Set(&crdv1alpha1.NetworkPolicyRuleGroup{ObjectMeta: v1ObjectMeta("a")})
	c.Set(&crdv1alpha1.NetworkPolicyRuleGroup{ObjectMeta: v1ObjectMeta("b")})

	removed := c.ReplaceAll([]*crdv1alpha1.NetworkPolicyRuleGroup{{ObjectMeta: v1ObjectMeta("b")}, {ObjectMeta: v1ObjectMeta("c")}})

	if len(removed) != 1 || removed[0] != "a" {
		t.Fatalf("removed = %v, want [a]", removed)
	}
	all, _ := c.List(labels.Everything())
	if len(all) != 2 {
		t.Fatalf("List after ReplaceAll = %d entries, want 2", len(all))
	}
}
