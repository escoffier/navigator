package microseg

import (
	"testing"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

var payloadRuleGroupFixture = crdv1alpha1.NetworkPolicyRuleGroup{
	ObjectMeta: v1.ObjectMeta{Name: "policy-node1"},
	Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{Policy: "policy", NodeName: "node1"},
}

func Test_RuleGroupStreamHandler_OnCreate_PopulatesCacheAndQueue(t *testing.T) {
	controller := NewStreamRuleGroupController(nil, "node1", nil, nil)
	h := &RuleGroupStreamHandler{Controller: controller}

	req := &pb.NetworkPolicyRuleGroupReq{RuleGroup: &pb.NetworkPolicyRuleGroupPayload{
		Name: "policy-node1", Policy: "policy", NodeName: "node1",
	}}
	h.OnCreate(nil, "reqid", req)

	rg, err := controller.streamCache.Get("policy-node1")
	if err != nil || rg.Spec.Policy != "policy" {
		t.Fatalf("cache after OnCreate: %+v, %v", rg, err)
	}
	if controller.queue.Len() != 1 {
		t.Fatalf("queue length = %d, want 1", controller.queue.Len())
	}
}

func Test_RuleGroupStreamHandler_OnDelete_RemovesFromCache(t *testing.T) {
	controller := NewStreamRuleGroupController(nil, "node1", nil, nil)
	controller.streamCache.Set(&payloadRuleGroupFixture)
	h := &RuleGroupStreamHandler{Controller: controller}

	req := &pb.NetworkPolicyRuleGroupReq{RuleGroup: &pb.NetworkPolicyRuleGroupPayload{Name: "policy-node1"}}
	h.OnDelete(nil, "reqid", req)

	if _, err := controller.streamCache.Get("policy-node1"); err == nil {
		t.Fatal("cache still has policy-node1 after OnDelete")
	}
}

func Test_RuleGroupSyncStreamHandler_OnCreate_ReplacesCacheAndEnqueuesRemovals(t *testing.T) {
	controller := NewStreamRuleGroupController(nil, "node1", nil, nil)
	controller.streamCache.Set(&payloadRuleGroupFixture) // pre-existing "policy-node1", not in the snapshot below
	h := &RuleGroupSyncStreamHandler{Controller: controller}

	req := &pb.NetworkPolicyRuleGroupSyncReq{RuleGroups: []*pb.NetworkPolicyRuleGroupPayload{
		{Name: "policy2-node1", Policy: "policy2", NodeName: "node1"},
	}}
	h.OnCreate(nil, "reqid", req)

	if _, err := controller.streamCache.Get("policy-node1"); err == nil {
		t.Fatal("stale entry policy-node1 still present after snapshot")
	}
	if _, err := controller.streamCache.Get("policy2-node1"); err != nil {
		t.Fatalf("policy2-node1 missing after snapshot: %v", err)
	}
	// one Add for the removed stale name, one for the new snapshot entry
	if controller.queue.Len() != 2 {
		t.Fatalf("queue length = %d, want 2", controller.queue.Len())
	}
}

// The stream-fed controller must not gate its worker on a bootstrap snapshot
// ever arriving: clustermanager only pushes one when the daemon is connected
// and registered, so waiting for it in Run's WaitForNamedCacheSync could block
// forever. ruleGroupSynced is therefore unconditionally true.
func Test_NewStreamRuleGroupController_SyncedWithoutSnapshot(t *testing.T) {
	controller := NewStreamRuleGroupController(nil, "node1", nil, nil)
	if !controller.ruleGroupSynced() {
		t.Fatal("ruleGroupSynced() = false before any snapshot, want true (worker must not block)")
	}
}
