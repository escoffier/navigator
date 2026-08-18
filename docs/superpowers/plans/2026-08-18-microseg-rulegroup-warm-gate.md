# Microseg rule-group "warm gate" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix [issue #2](https://github.com/escoffier/navigator/issues/2) — `pushedRuleGroupCache` is
in-memory only, so a node dropping out of a `ClusterNetworkPolicy`'s scope while clustermanager is
down never gets its DELETE sent after restart, and daemons connecting before clustermanager has
finished its first reconcile pass can get an empty/incomplete bootstrap snapshot that transiently
wipes correct state.

**Architecture:** Add a "warm" gate to `NetworkPolicyController`. Before it is warm (i.e. before
`Run` has completed one full synchronous reconcile pass over every `ClusterNetworkPolicy`),
`OnConnect` defers — it does not push any snapshot to a newly-connected daemon, correct or not. The
moment `Run` finishes that pass, the controller flips to warm and pushes a corrected snapshot to
every daemon connection that already exists at that instant (whether it connected before or during
the reconcile pass), sourced fresh from `pushedRuleGroupCache`. This requires the streaming
framework to expose which node keys are currently connected, which it doesn't today.

**Tech Stack:** Go, `k8s.io/client-go` listers/informers, existing `pkg/streaming` (`rpcstream`)
gRPC stream framework.

**Spec:** `docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md` (see its
"Known limitations" section, first bullet) and
[github.com/escoffier/navigator issue #2](https://github.com/escoffier/navigator/issues/2).

## Global Constraints

- Only affects the `MICROSEG_GRPC_ENABLED=true` path (`pushedCache`/`onConnectStream` non-nil). The
  CRD/informer path (`MICROSEG_GRPC_ENABLED` unset) must be byte-for-byte unchanged.
- No dual-write, no new env flags — this only fixes internal sequencing/state of the gRPC path
  already gated by the existing `MICROSEG_GRPC_ENABLED` flag.
- Follow existing code style in the touched files: `logging.Get()...` for logs (not `log.Printf`),
  narrow interfaces for testability (see `ruleGroupStreamPusher` / `ruleGroupOnConnectStream`
  pattern already in the file), table-free small focused unit tests matching the existing
  `Test_RegisterOnConnect_*` / `Test_grpcRuleGroupPusher_*` style.
- `.golangci.yml`: keep functions well under `cyclop` max-complexity 20, lines under 150 cols
  (`lll`), imports grouped/sorted per `goimports` local-prefix `gitlab.com/piccolo_su/vegeta`.

---

## Task 1: Expose currently-connected node keys from the streaming framework

**Files:**
- Modify: `pkg/streaming/streamfactory.go`
- Test: `pkg/streaming/rulegroup_client_test.go`

**Interfaces:**
- Produces: `MessageStream.ConnectedNodeKeys() []string` — returns the node keys of every stream
  currently registered in `messageStream.streams`. Implemented once on `messageStream`, so both
  `messageStreamServer` and `messageStreamClient` (which embed it) get it automatically.

- [ ] **Step 1: Write the failing test**

Add to `pkg/streaming/rulegroup_client_test.go` (this file already defines `fakeStream` and
builds bare `messageStream{streams: ...}` values, so no new fixtures are needed):

```go
func Test_messageStream_ConnectedNodeKeys(t *testing.T) {
	s := &messageStream{streams: map[string]Stream{
		"node1-daemon": &fakeStream{},
		"node2-daemon": &fakeStream{},
	}}

	got := s.ConnectedNodeKeys()
	want := map[string]bool{"node1-daemon": true, "node2-daemon": true}
	if len(got) != len(want) {
		t.Fatalf("ConnectedNodeKeys() = %v, want keys %v", got, want)
	}
	for _, k := range got {
		if !want[k] {
			t.Errorf("unexpected key %q in ConnectedNodeKeys()", k)
		}
	}
}

func Test_messageStream_ConnectedNodeKeys_Empty(t *testing.T) {
	s := &messageStream{streams: map[string]Stream{}}
	if got := s.ConnectedNodeKeys(); len(got) != 0 {
		t.Fatalf("ConnectedNodeKeys() = %v, want empty", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/streaming/... -run Test_messageStream_ConnectedNodeKeys -v`
Expected: FAIL with `s.ConnectedNodeKeys undefined`.

- [ ] **Step 3: Add `ConnectedNodeKeys` to the `MessageStream` interface and implement it**

In `pkg/streaming/streamfactory.go`, find:

```go
type MessageStream interface {
	MessageStreamClient
	Start() error
	AddHandler(msg protoreflect.ProtoMessage, handler MessageHandler) error
	AddHandlerFunc(msg protoreflect.ProtoMessage, f ProcessFunc) error
	Response(stream Stream, reqUUID string, resp protoreflect.ProtoMessage) error
	DumpStreams() string
	OnConnect(f func(nodeKey string))
}
```

Replace with:

```go
type MessageStream interface {
	MessageStreamClient
	Start() error
	AddHandler(msg protoreflect.ProtoMessage, handler MessageHandler) error
	AddHandlerFunc(msg protoreflect.ProtoMessage, f ProcessFunc) error
	Response(stream Stream, reqUUID string, resp protoreflect.ProtoMessage) error
	DumpStreams() string
	OnConnect(f func(nodeKey string))
	// ConnectedNodeKeys returns the node keys of every stream currently
	// registered (i.e. connected right now). Used to catch up already-connected
	// peers when a consumer's local state transitions from "not ready" to
	// "ready" after OnConnect may have already fired for them.
	ConnectedNodeKeys() []string
}
```

Then find:

```go
func (s *messageStream) OnConnect(f func(nodeKey string)) {
	s.streamLock.Lock()
	defer s.streamLock.Unlock()
	s.onConnect = f
}
```

Add immediately after it:

```go
func (s *messageStream) ConnectedNodeKeys() []string {
	s.streamLock.Lock()
	defer s.streamLock.Unlock()
	keys := make([]string, 0, len(s.streams))
	for k := range s.streams {
		keys = append(keys, k)
	}
	return keys
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/streaming/... -run Test_messageStream_ConnectedNodeKeys -v`
Expected: PASS (both subtests).

Run the full package to make sure nothing else broke: `go test ./pkg/streaming/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/streaming/streamfactory.go pkg/streaming/rulegroup_client_test.go
git commit -m "feat(streaming): expose currently-connected node keys via ConnectedNodeKeys"
```

---

## Task 2: Defer `RegisterOnConnect`'s push until the controller is warm

**Files:**
- Modify: `cmd/clustermanager/pkg/microseg/networkpolicy_controller.go`
- Test: `cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go`

**Interfaces:**
- Consumes: nothing new from Task 1 (this task only needs `OnConnect`/`PushRuleGroupSync`, already
  on `ruleGroupOnConnectStream`).
- Produces:
  - `NetworkPolicyController.onConnectStream ruleGroupOnConnectStream` field (set by
    `RegisterOnConnect`, consumed by Task 3's `markWarmAndSync`).
  - `NetworkPolicyController.warm bool` + `warmMu sync.Mutex` fields.
  - `(npc *NetworkPolicyController) isWarm() bool`.
  - `(npc *NetworkPolicyController) pushSnapshotToNode(stream ruleGroupOnConnectStream, nodeKey string)`
    — extracted from the old inline `RegisterOnConnect` body; Task 3's `markWarmAndSync` reuses it.

- [ ] **Step 1: Write the failing test**

Add to `cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go` (near the existing
`Test_RegisterOnConnect_*` tests):

```go
func Test_RegisterOnConnect_DeferredWhileNotWarm(t *testing.T) {
	cache := newPushedRuleGroupCache()
	cache.Set(&crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "policy-node1"},
		Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{Policy: "policy", NodeName: "node1"},
	})
	npc := &NetworkPolicyController{pushedCache: cache} // warm defaults to false
	fake := &fakeOnConnectStream{}
	npc.RegisterOnConnect(fake)

	fake.onConnect("node1-daemon")

	if len(fake.pushed) != 0 {
		t.Fatalf("pushed = %+v, want no pushes before clustermanager is warm", fake.pushed)
	}
}
```

Also update the two existing tests that assert an *immediate* push on connect — they now need to
simulate a warm controller. In `Test_RegisterOnConnect_EmptyNodeStillGetsSnapshot`, change:

```go
	npc := &NetworkPolicyController{pushedCache: newPushedRuleGroupCache()}
```

to:

```go
	npc := &NetworkPolicyController{pushedCache: newPushedRuleGroupCache(), warm: true}
```

And in `Test_RegisterOnConnect_NodeWithRuleGroups`, change:

```go
	npc := &NetworkPolicyController{pushedCache: cache}
```

to:

```go
	npc := &NetworkPolicyController{pushedCache: cache, warm: true}
```

(`Test_RegisterOnConnect_IgnoresNonDaemonSuffix` and `Test_RegisterOnConnect_NilCacheIsNoop` need
no change — they return before the warm check either way.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_RegisterOnConnect -v`
Expected: FAIL — `unknown field warm in struct literal` (struct doesn't have the field yet), and/or
`Test_RegisterOnConnect_DeferredWhileNotWarm` failing because today's code pushes unconditionally.

- [ ] **Step 3: Add warm state and gate the push**

In `cmd/clustermanager/pkg/microseg/networkpolicy_controller.go`, add `"sync"` to the stdlib import
group (alphabetically between `"strings"` and `"time"`):

```go
import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
```

Find the `NetworkPolicyController` struct's tail:

```go
	firstSynced         map[string]bool
	ruleGroupMap        map[string]sets.String
	pushedCache         *pushedRuleGroupCache
	ruleGroupPusher     ruleGroupPusher
}
```

Replace with:

```go
	firstSynced         map[string]bool
	ruleGroupMap        map[string]sets.String
	pushedCache         *pushedRuleGroupCache
	ruleGroupPusher     ruleGroupPusher

	// onConnectStream, warmMu and warm implement the issue #2 "warm gate":
	// RegisterOnConnect defers pushing a bootstrap snapshot to a connecting
	// daemon until warm is true, and markWarmAndSync (Task 3) flips warm to
	// true and catches up already-connected daemons at that point. Both nil
	// unless MICROSEG_GRPC_ENABLED (i.e. pushedCache is also non-nil).
	onConnectStream ruleGroupOnConnectStream
	warmMu          sync.Mutex
	warm            bool
}
```

Now find the existing `RegisterOnConnect` method and its doc comment:

```go
// RegisterOnConnect wires this controller's pushed-rule-group cache to the
// stream's OnConnect hook, so a (re)connecting daemon receives a full
// bootstrap snapshot of the rule groups clustermanager has already computed
// for its node — the gRPC-push equivalent of the initial List a k8s informer
// gets for free. No-op for node keys that aren't a daemon connection (e.g.
// "-monitor", which shares the same in-cluster stream).
func (npc *NetworkPolicyController) RegisterOnConnect(stream ruleGroupOnConnectStream) {
	stream.OnConnect(func(nodeKey string) {
		if !strings.HasSuffix(nodeKey, daemonNodeKeySuffix) || npc.pushedCache == nil {
			return
		}
		nodeName := strings.TrimSuffix(nodeKey, daemonNodeKeySuffix)
		groups := npc.pushedCache.ListForNode(nodeName)
		req := &pb.NetworkPolicyRuleGroupSyncReq{}
		for _, rg := range groups {
			req.RuleGroups = append(req.RuleGroups, ruleGroupToPayload(rg))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := stream.PushRuleGroupSync(ctx, nodeKey, req); err != nil {
			logging.Get().Err(err).Str("nodeKey", nodeKey).Msg("push rule group bootstrap snapshot")
			return
		}
		logging.Get().Info().Str("nodeKey", nodeKey).Int("ruleGroups", len(groups)).Msg("pushed rule group bootstrap snapshot")
	})
}
```

Replace the whole thing with:

```go
// RegisterOnConnect wires this controller's pushed-rule-group cache to the
// stream's OnConnect hook, so a (re)connecting daemon receives a full
// bootstrap snapshot of the rule groups clustermanager has already computed
// for its node — the gRPC-push equivalent of the initial List a k8s informer
// gets for free. No-op for node keys that aren't a daemon connection (e.g.
// "-monitor", which shares the same in-cluster stream).
//
// Before the controller is warm (see markWarmAndSync), the callback defers
// entirely rather than pushing a possibly-empty/incomplete snapshot — doing
// so could transiently wipe correct state on a daemon that already has it
// (issue #2). markWarmAndSync catches up any daemon that connected during
// this deferred window once the controller becomes warm.
func (npc *NetworkPolicyController) RegisterOnConnect(stream ruleGroupOnConnectStream) {
	npc.onConnectStream = stream
	stream.OnConnect(func(nodeKey string) {
		if !strings.HasSuffix(nodeKey, daemonNodeKeySuffix) || npc.pushedCache == nil {
			return
		}
		if !npc.isWarm() {
			logging.Get().Info().Str("nodeKey", nodeKey).
				Msg("deferring rule group bootstrap snapshot until clustermanager completes its initial reconcile")
			return
		}
		npc.pushSnapshotToNode(stream, nodeKey)
	})
}

func (npc *NetworkPolicyController) isWarm() bool {
	npc.warmMu.Lock()
	defer npc.warmMu.Unlock()
	return npc.warm
}

// pushSnapshotToNode sends nodeKey's full pushedCache-derived rule group set
// as one NetworkPolicyRuleGroupSyncReq. Shared by RegisterOnConnect's
// post-warm connect path and markWarmAndSync's warm-transition catch-up
// (Task 3).
func (npc *NetworkPolicyController) pushSnapshotToNode(stream ruleGroupOnConnectStream, nodeKey string) {
	nodeName := strings.TrimSuffix(nodeKey, daemonNodeKeySuffix)
	groups := npc.pushedCache.ListForNode(nodeName)
	req := &pb.NetworkPolicyRuleGroupSyncReq{}
	for _, rg := range groups {
		req.RuleGroups = append(req.RuleGroups, ruleGroupToPayload(rg))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := stream.PushRuleGroupSync(ctx, nodeKey, req); err != nil {
		logging.Get().Err(err).Str("nodeKey", nodeKey).Msg("push rule group snapshot")
		return
	}
	logging.Get().Info().Str("nodeKey", nodeKey).Int("ruleGroups", len(groups)).Msg("pushed rule group snapshot")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_RegisterOnConnect -v`
Expected: PASS (all `Test_RegisterOnConnect_*` subtests, including the new deferred one).

- [ ] **Step 5: Commit**

```bash
git add cmd/clustermanager/pkg/microseg/networkpolicy_controller.go cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go
git commit -m "fix(clustermanager/microseg): defer rule group bootstrap snapshot until warm"
```

---

## Task 3: `markWarmAndSync` — flip warm and catch up already-connected daemons

**Files:**
- Modify: `cmd/clustermanager/pkg/microseg/networkpolicy_controller.go`
- Test: `cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go`

**Interfaces:**
- Consumes: Task 1's `ConnectedNodeKeys() []string` (added to the real `rpcstream.MessageStream`);
  Task 2's `onConnectStream`, `warmMu`, `warm`, `isWarm()`, `pushSnapshotToNode`.
- Produces: `(npc *NetworkPolicyController) markWarmAndSync()`, called by Task 4's `Run()`.

- [ ] **Step 1: Write the failing test**

Add to `cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go`. First extend the
existing `fakeOnConnectStream` type (defined near the other `Test_RegisterOnConnect_*` tests) with
a `connectedKeys` field and a `ConnectedNodeKeys` method — find:

```go
type fakeOnConnectStream struct {
	onConnect func(string)
	pushed    []struct {
		nodeKey string
		req     *pb.NetworkPolicyRuleGroupSyncReq
	}
}

func (f *fakeOnConnectStream) OnConnect(fn func(string)) { f.onConnect = fn }
```

Replace with:

```go
type fakeOnConnectStream struct {
	onConnect     func(string)
	connectedKeys []string
	pushed        []struct {
		nodeKey string
		req     *pb.NetworkPolicyRuleGroupSyncReq
	}
}

func (f *fakeOnConnectStream) OnConnect(fn func(string)) { f.onConnect = fn }

func (f *fakeOnConnectStream) ConnectedNodeKeys() []string { return f.connectedKeys }
```

Then add the new tests:

```go
func Test_MarkWarmAndSync_PushesToAlreadyConnectedDaemons(t *testing.T) {
	cache := newPushedRuleGroupCache()
	cache.Set(&crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "policy-node1"},
		Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{Policy: "policy", NodeName: "node1"},
	})
	npc := &NetworkPolicyController{pushedCache: cache}
	fake := &fakeOnConnectStream{connectedKeys: []string{"node1-daemon", "node2-daemon", "node3-monitor"}}
	npc.RegisterOnConnect(fake)

	if npc.isWarm() {
		t.Fatal("controller warm before markWarmAndSync")
	}

	npc.markWarmAndSync()

	if !npc.isWarm() {
		t.Fatal("controller not warm after markWarmAndSync")
	}
	if len(fake.pushed) != 2 {
		t.Fatalf("pushed = %+v, want 2 pushes (node1-daemon, node2-daemon), node3-monitor excluded", fake.pushed)
	}
	pushedTo := map[string]int{}
	for _, p := range fake.pushed {
		pushedTo[p.nodeKey] = len(p.req.GetRuleGroups())
	}
	if n, ok := pushedTo["node1-daemon"]; !ok || n != 1 {
		t.Errorf("node1-daemon pushed %d rule groups, want 1", n)
	}
	if n, ok := pushedTo["node2-daemon"]; !ok || n != 0 {
		t.Errorf("node2-daemon pushed %d rule groups, want 0 (empty snapshot)", n)
	}
}

func Test_MarkWarmAndSync_NilOnConnectStreamIsNoop(t *testing.T) {
	npc := &NetworkPolicyController{pushedCache: newPushedRuleGroupCache()}
	npc.markWarmAndSync()
	if npc.isWarm() {
		t.Fatal("controller marked warm despite no onConnectStream")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_MarkWarmAndSync -v`
Expected: FAIL — `npc.markWarmAndSync undefined`, and `ruleGroupOnConnectStream` doesn't yet require
`ConnectedNodeKeys` so this won't even compile cleanly against the plan's intent yet (that's fixed
in Step 3 below, along with the method itself).

- [ ] **Step 3: Extend the interface and implement `markWarmAndSync`**

In `cmd/clustermanager/pkg/microseg/networkpolicy_controller.go`, find:

```go
type ruleGroupOnConnectStream interface {
	OnConnect(f func(nodeKey string))
	PushRuleGroupSync(ctx context.Context, nodeKey string, req *pb.NetworkPolicyRuleGroupSyncReq) error
}
```

Replace with:

```go
type ruleGroupOnConnectStream interface {
	OnConnect(f func(nodeKey string))
	PushRuleGroupSync(ctx context.Context, nodeKey string, req *pb.NetworkPolicyRuleGroupSyncReq) error
	// ConnectedNodeKeys returns node keys connected right now, used by
	// markWarmAndSync to catch up daemons that connected before the
	// controller became warm.
	ConnectedNodeKeys() []string
}
```

Then, immediately after `pushSnapshotToNode` (added in Task 2), add:

```go
// markWarmAndSync flips the controller to "warm" — meaning it has completed
// one full reconcile pass over every ClusterNetworkPolicy and pushedCache
// now reflects true desired state (see issue #2) — then pushes a corrected
// snapshot to every daemon connection that exists at that instant. Those
// daemons either got no snapshot yet (RegisterOnConnect defers while not
// warm) or connected and were skipped for the same reason; either way this
// is the single source-of-truth correction. Called once, from Run.
func (npc *NetworkPolicyController) markWarmAndSync() {
	if npc.onConnectStream == nil {
		return
	}
	npc.warmMu.Lock()
	npc.warm = true
	nodeKeys := npc.onConnectStream.ConnectedNodeKeys()
	npc.warmMu.Unlock()

	for _, nodeKey := range nodeKeys {
		if !strings.HasSuffix(nodeKey, daemonNodeKeySuffix) {
			continue
		}
		npc.pushSnapshotToNode(npc.onConnectStream, nodeKey)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run 'Test_MarkWarmAndSync|Test_RegisterOnConnect' -v`
Expected: PASS (all subtests).

Run the whole package to catch any other fallout: `go test ./cmd/clustermanager/pkg/microseg/...`
Expected: PASS. (If the package fails to build because `rpcstream.MessageStream` no longer
satisfies `ruleGroupOnConnectStream`, Task 1 wasn't applied first — go back and confirm
`ConnectedNodeKeys` exists on `messageStream`.)

- [ ] **Step 5: Commit**

```bash
git add cmd/clustermanager/pkg/microseg/networkpolicy_controller.go cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go
git commit -m "fix(clustermanager/microseg): catch up already-connected daemons at warm transition"
```

---

## Task 4: Run one full reconcile pass before starting the worker, then mark warm

**Files:**
- Modify: `cmd/clustermanager/pkg/microseg/networkpolicy_controller.go`
- Test: `cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go`

**Interfaces:**
- Consumes: Task 3's `markWarmAndSync()`; existing `npc.policyLister`, `npc.syncPolicy(key string) error`,
  `KeyFunc` (package-level `var KeyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc`, already used
  elsewhere in this file, e.g. `addClusterPolicy`).
- Produces: `(npc *NetworkPolicyController) reconcileAllPolicies()`, called only from `Run`.

- [ ] **Step 1: Write the failing test**

Add to `cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go`. This test drives the
"disabled policy" branch of `syncPolicy` (`deleteRuleGroup` → `ruleGroupPusher.DeleteByPolicy`)
since it needs no pod/namespace/service listers — just a `policyLister` and a `ruleGroupPusher`:

```go
func Test_reconcileAllPolicies_SyncsEveryPolicy(t *testing.T) {
	crdClient := crdfake.NewSimpleClientset()
	crdFactory := externalversions.NewSharedInformerFactory(crdClient, time.Hour)
	policyStore := crdFactory.Microsegmentation().V1alpha1().ClusterNetworkPolicies().Informer().GetIndexer()

	policyStore.Add(&crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{Name: "policy-a"},
		Spec:       crdv1alpha1.ClusterNetworkPolicySpec{Enable: false},
	})
	policyStore.Add(&crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{Name: "policy-b"},
		Spec:       crdv1alpha1.ClusterNetworkPolicySpec{Enable: false},
	})

	cache := newPushedRuleGroupCache()
	cache.Set(&crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "policy-a-node1", Labels: map[string]string{"kubernetes.io/networkpolicy-name": "policy-a"}},
		Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{NodeName: "node1"},
	})
	cache.Set(&crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "policy-b-node2", Labels: map[string]string{"kubernetes.io/networkpolicy-name": "policy-b"}},
		Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{NodeName: "node2"},
	})
	stream := &fakeRuleGroupStream{}

	npc := &NetworkPolicyController{
		policyLister:    crdFactory.Microsegmentation().V1alpha1().ClusterNetworkPolicies().Lister(),
		ruleGroupMap:    make(map[string]sets.String),
		firstSynced:     make(map[string]bool),
		ruleGroupPusher: &grpcRuleGroupPusher{cache: cache, stream: stream},
	}

	npc.reconcileAllPolicies()

	if all, _ := cache.List(nil); len(all) != 0 {
		t.Fatalf("pushedCache not drained by reconcile: %+v", all)
	}
	if len(stream.pushed) != 2 {
		t.Fatalf("pushed %d messages, want 2 DELETEs", len(stream.pushed))
	}
	for _, p := range stream.pushed {
		if p.msgType != pb.MessageType_DELETE {
			t.Errorf("msgType = %v, want DELETE", p.msgType)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_reconcileAllPolicies -v`
Expected: FAIL — `npc.reconcileAllPolicies undefined`.

- [ ] **Step 3: Implement `reconcileAllPolicies` and wire it (plus `markWarmAndSync`) into `Run`**

In `cmd/clustermanager/pkg/microseg/networkpolicy_controller.go`, find:

```go
func (npc *NetworkPolicyController) Run(stopChan chan struct{}) {
	logging.Get().Info().Msg("run Network Policy Controller")
	if !cache.WaitForNamedCacheSync("network_policy", stopChan,
		npc.podSynced, npc.namepaceSynced, npc.clusterPolicySynced, npc.clusterGroupSynced, npc.ruleGroupSynced) {
		return
	}
	go wait.Until(npc.worker, time.Second, stopChan)
	// go wait.Until(npc.nodeWorker, time.Second, stopChan)
}
```

Replace with:

```go
func (npc *NetworkPolicyController) Run(stopChan chan struct{}) {
	logging.Get().Info().Msg("run Network Policy Controller")
	if !cache.WaitForNamedCacheSync("network_policy", stopChan,
		npc.podSynced, npc.namepaceSynced, npc.clusterPolicySynced, npc.clusterGroupSynced, npc.ruleGroupSynced) {
		return
	}
	// Only the gRPC push path (onConnectStream set) needs the warm gate: the
	// CRD path's "current state" already comes durably from k8s, so it has
	// no equivalent gap to close (issue #2). This runs synchronously, before
	// the async worker below starts, so nothing else touches
	// ruleGroupMap/firstSynced concurrently during the pass.
	if npc.onConnectStream != nil {
		npc.reconcileAllPolicies()
		npc.markWarmAndSync()
	}
	go wait.Until(npc.worker, time.Second, stopChan)
	// go wait.Until(npc.nodeWorker, time.Second, stopChan)
}

// reconcileAllPolicies synchronously runs syncPolicy for every
// ClusterNetworkPolicy currently known to the lister. This is the "one full
// reconcile pass" issue #2's warm gate requires: it guarantees
// pushedRuleGroupCache reflects true desired state for every policy before
// markWarmAndSync starts serving bootstrap snapshots from it.
func (npc *NetworkPolicyController) reconcileAllPolicies() {
	policies, err := npc.policyLister.List(labels.Everything())
	if err != nil {
		logging.Get().Err(err).Msg("list cluster network policies for initial reconcile")
		return
	}
	for _, p := range policies {
		key, err := KeyFunc(p)
		if err != nil {
			logging.Get().Err(err).Str("policy", p.Name).Msg("build key for initial reconcile")
			continue
		}
		if err := npc.syncPolicy(key); err != nil {
			logging.Get().Err(err).Str("policy", p.Name).Msg("initial reconcile of policy")
		}
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_reconcileAllPolicies -v`
Expected: PASS.

Run the full package and the streaming package once more: `go test ./cmd/clustermanager/pkg/microseg/... ./pkg/streaming/...`
Expected: PASS.

Run `go build ./...` from the repo root to confirm `cmd/clustermanager/cmd/server.go` (which calls
`microseg.NewNetworkPolicyController(...).Run(stopChan)` with no signature change) still compiles.
Expected: success.

- [ ] **Step 5: Commit**

```bash
git add cmd/clustermanager/pkg/microseg/networkpolicy_controller.go cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go
git commit -m "fix(clustermanager/microseg): run full policy reconcile before warm transition"
```

---

## Task 5: Document the fix in the migration spec

**Files:**
- Modify: `docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md`

**Interfaces:** None — documentation only.

- [ ] **Step 1: Update the "Known limitations" bullet for issue #2**

In `docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md`, find the first
bullet under "### Known limitations":

```
- **Non-durable pushed-state cache loses DELETEs across a clustermanager restart** (tracked as
  [#2](https://github.com/escoffier/navigator/issues/2)). Today's CRD
  write makes k8s the durable "current state" `syncPolicyRules` diffs against; `pushedRuleGroupCache`
  is in-memory only. If a node drops out of a policy's scope while clustermanager is down, the
  first reconcile after restart sees an empty "current" set and has nothing to diff the removal
  against, so no DELETE is ever sent — that node's daemon keeps enforcing the stale rule group
  indefinitely. A correct fix needs a "warm" gate: only start answering `OnConnect` bootstrap
  requests (including legitimately-empty ones) after clustermanager has completed one full
  reconcile pass over every `ClusterNetworkPolicy`, and push corrected snapshots to
  already-connected daemons at that warm transition — sending real snapshots before warm risks
  transiently wiping correct daemon state with an incomplete view.
```

Replace with:

```
- **Non-durable pushed-state cache loses DELETEs across a clustermanager restart** (tracked as
  [#2](https://github.com/escoffier/navigator/issues/2), fixed). Today's CRD
  write makes k8s the durable "current state" `syncPolicyRules` diffs against; `pushedRuleGroupCache`
  is in-memory only. If a node drops out of a policy's scope while clustermanager is down, the
  first reconcile after restart used to see an empty "current" set and have nothing to diff the
  removal against, so no DELETE was ever sent — that node's daemon would keep enforcing the stale
  rule group indefinitely. Fixed with a "warm" gate (`NetworkPolicyController.warm`,
  `reconcileAllPolicies`, `markWarmAndSync` in `networkpolicy_controller.go`): `OnConnect` now
  defers answering bootstrap requests (including legitimately-empty ones) until clustermanager has
  completed one full reconcile pass over every `ClusterNetworkPolicy`, and pushes corrected
  snapshots to already-connected daemons at that warm transition — avoiding the risk of a real
  snapshot sent before warm transiently wiping correct daemon state with an incomplete view.
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md
git commit -m "docs: mark issue #2 (non-durable pushed-state cache) as fixed in migration spec"
```
