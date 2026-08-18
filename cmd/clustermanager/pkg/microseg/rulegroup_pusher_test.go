package microseg

import (
	"context"
	"errors"
	"testing"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

type fakeRuleGroupStream struct {
	pushed []struct {
		nodeKey string
		msgType pb.MessageType
		req     *pb.NetworkPolicyRuleGroupReq
	}
	err error
}

func (f *fakeRuleGroupStream) PushRuleGroup(_ context.Context, nodeKey string, msgType pb.MessageType, req *pb.NetworkPolicyRuleGroupReq) error {
	if f.err != nil {
		return f.err
	}
	f.pushed = append(f.pushed, struct {
		nodeKey string
		msgType pb.MessageType
		req     *pb.NetworkPolicyRuleGroupReq
	}{nodeKey, msgType, req})
	return nil
}

func Test_grpcRuleGroupPusher_Create(t *testing.T) {
	cache := newPushedRuleGroupCache()
	stream := &fakeRuleGroupStream{}
	p := &grpcRuleGroupPusher{cache: cache, stream: stream}

	rg := &crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "policy-node1"},
		Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{Policy: "policy", NodeName: "node1"},
	}
	if err := p.Create(context.Background(), rg); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if len(stream.pushed) != 1 || stream.pushed[0].nodeKey != "node1-daemon" || stream.pushed[0].msgType != pb.MessageType_CREATE {
		t.Fatalf("pushed = %+v, want one CREATE to node1-daemon", stream.pushed)
	}
	if _, err := cache.Get("policy-node1"); err != nil {
		t.Fatalf("cache not updated after Create: %v", err)
	}
}

func Test_grpcRuleGroupPusher_Delete_TargetsCachedNode(t *testing.T) {
	cache := newPushedRuleGroupCache()
	cache.Set(&crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "policy-node1"},
		Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{NodeName: "node1"},
	})
	stream := &fakeRuleGroupStream{}
	p := &grpcRuleGroupPusher{cache: cache, stream: stream}

	if err := p.Delete(context.Background(), "policy-node1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(stream.pushed) != 1 || stream.pushed[0].nodeKey != "node1-daemon" || stream.pushed[0].msgType != pb.MessageType_DELETE {
		t.Fatalf("pushed = %+v, want one DELETE to node1-daemon", stream.pushed)
	}
	if _, err := cache.Get("policy-node1"); err == nil {
		t.Fatal("cache still has policy-node1 after Delete")
	}
}

func Test_grpcRuleGroupPusher_Delete_PushFailureKeepsCacheEntry(t *testing.T) {
	cache := newPushedRuleGroupCache()
	cache.Set(&crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "policy-node1"},
		Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{NodeName: "node1"},
	})
	stream := &fakeRuleGroupStream{err: errors.New("push failed")}
	p := &grpcRuleGroupPusher{cache: cache, stream: stream}

	if err := p.Delete(context.Background(), "policy-node1"); err == nil {
		t.Fatal("Delete: want error when push fails, got nil")
	}
	if _, err := cache.Get("policy-node1"); err != nil {
		t.Fatalf("cache entry removed despite failed push: %v", err)
	}
}

func Test_grpcRuleGroupPusher_Delete_UnknownNameIsNoop(t *testing.T) {
	p := &grpcRuleGroupPusher{cache: newPushedRuleGroupCache(), stream: &fakeRuleGroupStream{}}
	if err := p.Delete(context.Background(), "missing"); err != nil {
		t.Fatalf("Delete on unknown name: %v", err)
	}
}

func Test_grpcRuleGroupPusher_DeleteByPolicy(t *testing.T) {
	cache := newPushedRuleGroupCache()
	cache.Set(&crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "policy-node1", Labels: map[string]string{"kubernetes.io/networkpolicy-name": "policy"}},
		Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{NodeName: "node1"},
	})
	cache.Set(&crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "policy-node2", Labels: map[string]string{"kubernetes.io/networkpolicy-name": "policy"}},
		Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{NodeName: "node2"},
	})
	stream := &fakeRuleGroupStream{}
	p := &grpcRuleGroupPusher{cache: cache, stream: stream}

	if err := p.DeleteByPolicy(context.Background(), "policy"); err != nil {
		t.Fatalf("DeleteByPolicy: %v", err)
	}
	if len(stream.pushed) != 2 {
		t.Fatalf("pushed %d messages, want 2", len(stream.pushed))
	}
	if all, _ := cache.List(nil); len(all) != 0 {
		t.Fatalf("cache not empty after DeleteByPolicy: %+v", all)
	}
}
