# Clustermanager send-side rule-group push serialization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix [issue #4](https://github.com/escoffier/navigator/issues/4) — clustermanager's
`RegisterOnConnect` callback (bootstrap snapshot push, fired asynchronously per connecting daemon)
and `NetworkPolicyController.worker` (incremental CREATE/UPDATE/DELETE pushes) both
read/mutate `pushedRuleGroupCache` and enqueue pushes for the same node with no serialization
between the two goroutines. A snapshot computed before a concurrent `DELETE` can still be enqueued
after it, so the daemon (correctly, in true send order — issue #3 already fixed the receive side)
applies the `DELETE` then the stale snapshot, permanently resurrecting a deleted rule group.
`checkSync` can't detect this since it only compares the daemon's own cache against what's applied
locally, never against clustermanager's true state.

**Architecture:** Add a per-node mutex (`pushedRuleGroupCache.LockNode`) that every code path
which reads/mutates the cache for a node and then enqueues a push for that node must hold across
both steps as one atomic unit: `grpcRuleGroupPusher.Create/Update/Delete` (the incremental path)
and `NetworkPolicyController.pushSnapshotToNode` (the bootstrap-snapshot path, used by both
`RegisterOnConnect`'s per-connect callback and `markWarmAndSync`'s catch-up loop). Because the
underlying `PushRuleGroup`/`PushRuleGroupSync` calls are fire-and-forget (`ack=false`) and bottom
out in a non-blocking in-memory FIFO `Add` (confirmed during the final review of issue #2), holding
this lock across the enqueue call is cheap — no network I/O happens synchronously under the lock.
Whichever operation for a given node acquires the lock first completes its full
read/mutate-then-enqueue before the other can start, so the two pushes for that node are always
enqueued in true logical order, closing the race.

**Tech Stack:** Go, `sync.Mutex`, the existing `pkg/streaming` fire-and-forget push path (unchanged
by this plan).

**Spec:** `docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md` (see its
"Known limitations" section, third bullet) and
[github.com/escoffier/navigator issue #4](https://github.com/escoffier/navigator/issues/4).

## Global Constraints

- Only affects the `MICROSEG_GRPC_ENABLED=true` path — `pushedRuleGroupCache` doesn't exist on the
  CRD/informer path, so there is nothing to gate; this plan's changes are only reachable when that
  flag is on.
- No change to wire format, proto messages, or send-vs-receive semantics beyond serialization
  timing — `PushRuleGroup`/`PushRuleGroupSync`'s call signatures and the underlying
  `pkg/streaming` framework (already fixed for issue #3) are untouched.
- Follow existing code style: simple `map[string]*sync.Mutex` + guarding mutex (matches
  `pushedRuleGroupCache`'s existing `mu sync.RWMutex` + `byName map[...]` shape), narrow return
  type (`func()` unlock closure) rather than a bespoke lock-handle type.
- `.golangci.yml`: `lll` (150 cols), `goimports` grouping, `cyclop` max-complexity 20.

---

## Task 1: `pushedRuleGroupCache.LockNode` — the per-node locking primitive

**Files:**
- Modify: `cmd/clustermanager/pkg/microseg/rulegroup_cache.go`
- Test: `cmd/clustermanager/pkg/microseg/rulegroup_cache_test.go`

**Interfaces:**
- Produces: `(*pushedRuleGroupCache) LockNode(nodeName string) func()` — acquires (creating on
  first use) a per-node `*sync.Mutex` and returns its `Unlock` method as the caller's unlock
  closure. Consumed by Task 2's `grpcRuleGroupPusher` and `NetworkPolicyController.pushSnapshotToNode`.

- [ ] **Step 1: Write the failing tests**

Add `"time"` to `cmd/clustermanager/pkg/microseg/rulegroup_cache_test.go`'s import block — find:

```go
import (
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)
```

Replace with:

```go
import (
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)
```

Then add these two tests to the same file:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_pushedRuleGroupCache_LockNode -v`
Expected: FAIL — `c.LockNode undefined`.

- [ ] **Step 3: Add the `nodeLocks` field and `LockNode` method**

In `cmd/clustermanager/pkg/microseg/rulegroup_cache.go`, find:

```go
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
```

Replace with:

```go
// pushedRuleGroupCache tracks the NetworkPolicyRuleGroup objects most recently
// pushed to daemons over gRPC, replacing the round-trip through the k8s CRD +
// informer that syncPolicyRules used to rely on to know "what's out there now".
type pushedRuleGroupCache struct {
	mu     sync.RWMutex
	byName map[string]*crdv1alpha1.NetworkPolicyRuleGroup

	// nodeMu guards nodeLocks itself (lazy creation only); nodeLocks holds
	// one mutex per node name. Every code path that reads/mutates this
	// cache for a node and then enqueues a push for that node must acquire
	// it via LockNode across both steps, so a bootstrap snapshot and an
	// incremental delta for the same node can never be enqueued out of
	// order relative to each other (issue #4).
	nodeMu    sync.Mutex
	nodeLocks map[string]*sync.Mutex
}

func newPushedRuleGroupCache() *pushedRuleGroupCache {
	return &pushedRuleGroupCache{
		byName:    make(map[string]*crdv1alpha1.NetworkPolicyRuleGroup),
		nodeLocks: make(map[string]*sync.Mutex),
	}
}

// LockNode acquires (creating on first use) the per-node lock for nodeName
// and returns its Unlock method as the caller's unlock closure. Callers must
// hold it across "read/mutate the cache for this node" plus "enqueue the
// corresponding push" as one atomic unit — see the nodeLocks field comment.
func (c *pushedRuleGroupCache) LockNode(nodeName string) func() {
	c.nodeMu.Lock()
	l, ok := c.nodeLocks[nodeName]
	if !ok {
		l = &sync.Mutex{}
		c.nodeLocks[nodeName] = l
	}
	c.nodeMu.Unlock()
	l.Lock()
	return l.Unlock
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_pushedRuleGroupCache_LockNode -v`
Expected: PASS (both tests).

Run the rest of the existing cache tests to confirm nothing else broke:
`go test ./cmd/clustermanager/pkg/microseg/... -run Test_pushedRuleGroupCache -v`
Expected: PASS (all `Test_pushedRuleGroupCache_*` tests, old and new).

- [ ] **Step 5: Commit**

```bash
git add cmd/clustermanager/pkg/microseg/rulegroup_cache.go cmd/clustermanager/pkg/microseg/rulegroup_cache_test.go
git commit -m "feat(clustermanager/microseg): add per-node locking to pushedRuleGroupCache"
```

---

## Task 2: Wire `LockNode` into the incremental and bootstrap-snapshot push paths

**Files:**
- Modify: `cmd/clustermanager/pkg/microseg/rulegroup_pusher.go`
- Modify: `cmd/clustermanager/pkg/microseg/networkpolicy_controller.go`
- Test: `cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go`

**Interfaces:**
- Consumes: Task 1's `(*pushedRuleGroupCache) LockNode(nodeName string) func()`.

- [ ] **Step 1: Write the failing test**

Add `"sync"` to the stdlib import group in
`cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go` — find:

```go
import (
	"context"
	"flag"
	"path/filepath"
	"reflect"
	"testing"
	"time"
```

Replace with:

```go
import (
	"context"
	"flag"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
```

Then add this fake and test (near the existing `fakeRuleGroupStream`/`fakeOnConnectStream` types is
a good spot, but anywhere in the file works):

```go
// fakeRaceStream implements both ruleGroupStreamPusher (PushRuleGroup, used
// by grpcRuleGroupPusher) and ruleGroupOnConnectStream (OnConnect/
// PushRuleGroupSync/ConnectedNodeKeys, used by pushSnapshotToNode), so a
// single instance can stand in for both sides of the issue #4 race in one
// test.
type fakeRaceStream struct {
	onConnect    func(string)
	onPushDelete func() // called synchronously inside PushRuleGroup, before it returns
}

func (f *fakeRaceStream) PushRuleGroup(_ context.Context, _ string, _ pb.MessageType, _ *pb.NetworkPolicyRuleGroupReq) error {
	if f.onPushDelete != nil {
		f.onPushDelete()
	}
	return nil
}

func (f *fakeRaceStream) OnConnect(fn func(string))  { f.onConnect = fn }
func (f *fakeRaceStream) ConnectedNodeKeys() []string { return nil }
func (f *fakeRaceStream) PushRuleGroupSync(_ context.Context, _ string, _ *pb.NetworkPolicyRuleGroupSyncReq) error {
	return nil
}

func Test_pushSnapshotToNode_SerializesAgainstConcurrentDelete(t *testing.T) {
	cache := newPushedRuleGroupCache()
	cache.Set(&crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "policy-node1"},
		Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{NodeName: "node1"},
	})

	entered := make(chan struct{})
	proceed := make(chan struct{})
	var enteredOnce sync.Once
	stream := &fakeRaceStream{
		onPushDelete: func() {
			enteredOnce.Do(func() { close(entered) })
			<-proceed
		},
	}
	pusher := &grpcRuleGroupPusher{cache: cache, stream: stream}
	npc := &NetworkPolicyController{pushedCache: cache}

	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- pusher.Delete(context.Background(), "policy-node1")
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("Delete's PushRuleGroup call never entered")
	}
	// Delete is now holding node1's lock, blocked inside PushRuleGroup.

	snapshotDone := make(chan struct{})
	go func() {
		npc.pushSnapshotToNode(stream, "node1-daemon")
		close(snapshotDone)
	}()

	select {
	case <-snapshotDone:
		t.Fatal("pushSnapshotToNode proceeded while Delete still held node1's lock")
	case <-time.After(150 * time.Millisecond):
	}

	close(proceed)

	select {
	case err := <-deleteDone:
		if err != nil {
			t.Fatalf("Delete: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Delete never completed after proceed was closed")
	}

	select {
	case <-snapshotDone:
	case <-time.After(2 * time.Second):
		t.Fatal("pushSnapshotToNode never completed after Delete released node1's lock")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_pushSnapshotToNode_SerializesAgainstConcurrentDelete -v -timeout 10s`
Expected: FAIL — either a compile error (before wiring) or, if it compiles, the test fails because
`pushSnapshotToNode` proceeds concurrently with `Delete` (no lock exists yet) — the
`t.Fatal("pushSnapshotToNode proceeded while Delete still held node1's lock")` line fires.

- [ ] **Step 3: Wire `LockNode` into `grpcRuleGroupPusher.Create/Update/Delete`**

In `cmd/clustermanager/pkg/microseg/rulegroup_pusher.go`, find:

```go
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
```

Replace with:

```go
func (p *grpcRuleGroupPusher) Create(ctx context.Context, rg *crdv1alpha1.NetworkPolicyRuleGroup) error {
	unlock := p.cache.LockNode(rg.Spec.NodeName)
	defer unlock()
	p.cache.Set(rg)
	req := &pb.NetworkPolicyRuleGroupReq{RuleGroup: ruleGroupToPayload(rg)}
	return p.stream.PushRuleGroup(ctx, rg.Spec.NodeName+daemonNodeKeySuffix, pb.MessageType_CREATE, req)
}

func (p *grpcRuleGroupPusher) Update(ctx context.Context, _, desired *crdv1alpha1.NetworkPolicyRuleGroup) error {
	unlock := p.cache.LockNode(desired.Spec.NodeName)
	defer unlock()
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
	unlock := p.cache.LockNode(rg.Spec.NodeName)
	defer unlock()
	req := &pb.NetworkPolicyRuleGroupReq{RuleGroup: &pb.NetworkPolicyRuleGroupPayload{Name: name}}
	if err := p.stream.PushRuleGroup(ctx, rg.Spec.NodeName+daemonNodeKeySuffix, pb.MessageType_DELETE, req); err != nil {
		return err
	}
	p.cache.Delete(name)
	return nil
}
```

(`DeleteByPolicy` is unchanged — it calls `p.Delete` per rule group, and `Delete` now locks its own
node internally on each call.)

- [ ] **Step 4: Wire `LockNode` into `pushSnapshotToNode`, and update the now-resolved comment in `Run`**

In `cmd/clustermanager/pkg/microseg/networkpolicy_controller.go`, find:

```go
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

Replace with:

```go
func (npc *NetworkPolicyController) pushSnapshotToNode(stream ruleGroupOnConnectStream, nodeKey string) {
	nodeName := strings.TrimSuffix(nodeKey, daemonNodeKeySuffix)
	unlock := npc.pushedCache.LockNode(nodeName)
	defer unlock()
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

Then find the comment above the worker-goroutine start in `Run` (this was rewritten during issue
#3's final-review fix wave to describe #4 as still-open):

```go
	// This worker's first incremental deltas, once it starts, are applied by
	// the daemon strictly after the warm-transition snapshot just pushed
	// above: both microseg rule-group message types are registered via
	// AddOrderedHandler (see pkg/streaming/stream.go), so pkg/streaming no
	// longer reorders them on receipt (issue #3, fixed). A different,
	// still-open race remains on the SEND side: RegisterOnConnect's callback
	// (fired asynchronously per connecting daemon) and this worker both
	// read/mutate pushedCache and enqueue pushes for the same node with no
	// serialization between the two goroutines, so a bootstrap snapshot
	// computed before a concurrent DELETE can still be enqueued after it,
	// resurrecting a rule group — checkSync only warns, it doesn't
	// self-heal. Tracked by issue #4.
	go wait.Until(npc.worker, time.Second, stopChan)
```

Replace with:

```go
	// This worker's first incremental deltas, once it starts, are applied by
	// the daemon strictly after the warm-transition snapshot just pushed
	// above: both microseg rule-group message types are registered via
	// AddOrderedHandler (see pkg/streaming/stream.go), so pkg/streaming no
	// longer reorders them on receipt (issue #3, fixed). RegisterOnConnect's
	// callback (fired asynchronously per connecting daemon) and this worker
	// both read/mutate pushedCache and enqueue pushes for the same node —
	// pushedRuleGroupCache.LockNode serializes the two so a bootstrap
	// snapshot and a concurrent delta for the same node are always enqueued
	// in the order their cache read/mutation actually happened, closing the
	// send-side race issue #4 described (fixed).
	go wait.Until(npc.worker, time.Second, stopChan)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_pushSnapshotToNode_SerializesAgainstConcurrentDelete -v -timeout 10s`
Expected: PASS.

Run the broader set of tests this plan touches (this scoped run avoids the package's pre-existing,
unrelated failing tests — see note below):
`go test ./cmd/clustermanager/pkg/microseg/... -run 'Test_pushedRuleGroupCache|Test_grpcRuleGroupPusher|Test_RegisterOnConnect|Test_MarkWarmAndSync|Test_reconcileAllPolicies|Test_syncPolicyRules_UsesInjectedPusher|Test_pushSnapshotToNode' -v`
Expected: PASS (all of them, old and new).

**Known pre-existing, out-of-scope failures in this package (do not fix, do not treat as
regressions):** `TestNetworkPolicyController_caculatePolicy`, `TestPolicyIndex`,
`TestNetworkPolicyController_caculateAddressMap`, `TestNetworkPolicyController_caculateNodeRules`
(pointer-vs-nil `PodReference` mismatches predating all of this work), `TestCreateCRD` (needs a
live envtest apiserver), `Test_getServicePort` (pre-existing panic).

- [ ] **Step 6: Commit**

```bash
git add cmd/clustermanager/pkg/microseg/rulegroup_pusher.go cmd/clustermanager/pkg/microseg/networkpolicy_controller.go cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go
git commit -m "fix(clustermanager/microseg): serialize bootstrap-snapshot and incremental pushes per node"
```

---

## Task 3: Document the fix in the migration spec

**Files:**
- Modify: `docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md`

**Interfaces:** None — documentation only.

- [ ] **Step 1: Update the "Known limitations" intro and the issue #4 bullet**

In `docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md`, find:

```
### Known limitations (surfaced across two rounds of final whole-branch review)

Three gaps have been found here, all architectural rather than implementation bugs. The two
original gaps are now fixed (see below); a third, newly-surfaced gap remains open and still blocks
enabling `MICROSEG_GRPC_ENABLED=true` in production on clusters with daemons reconnecting while
policy is actively changing:
```

Replace with:

```
### Known limitations (surfaced across two rounds of final whole-branch review)

Three gaps were found here, all architectural rather than implementation bugs — all three are now
fixed:
```

Then find the final bullet (issue #4):

```
- **Clustermanager send-side race between a bootstrap snapshot and a concurrent incremental delta
  for the same node** (tracked as
  [#4](https://github.com/escoffier/navigator/issues/4)). `RegisterOnConnect`'s callback (fired
  asynchronously per connecting daemon) and `NetworkPolicyController.worker` both read/mutate
  `pushedRuleGroupCache` and enqueue pushes for the same node with no serialization between the two
  goroutines: a snapshot computed before a concurrent `DELETE` can still be enqueued after it, so
  the daemon (correctly, in the order things were actually sent — issue #3 is fixed) applies the
  `DELETE` then the stale snapshot, resurrecting the deleted rule group permanently. `checkSync`
  can't detect this — it only compares the daemon's own cache against what's applied locally, not
  against clustermanager's true state. Needs pushes for a given node serialized across
  `RegisterOnConnect`'s bootstrap push and `grpcRuleGroupPusher`'s incremental pushes (e.g. a small
  per-node mutex or single-goroutine-per-node queue).
```

Replace with:

```
- **Clustermanager send-side race between a bootstrap snapshot and a concurrent incremental delta
  for the same node** (tracked as
  [#4](https://github.com/escoffier/navigator/issues/4), fixed). `RegisterOnConnect`'s callback
  (fired asynchronously per connecting daemon) and `NetworkPolicyController.worker` both read/mutate
  `pushedRuleGroupCache` and enqueue pushes for the same node; without serialization, a snapshot
  computed before a concurrent `DELETE` could still have been enqueued after it, so the daemon
  (correctly, in the order things were actually sent — issue #3 is fixed) would apply the `DELETE`
  then the stale snapshot, resurrecting the deleted rule group permanently — undetectable by
  `checkSync`, which only compares the daemon's own cache against what's applied locally, not
  against clustermanager's true state. Fixed with `pushedRuleGroupCache.LockNode`
  (`rulegroup_cache.go`): a per-node mutex that `grpcRuleGroupPusher.Create/Update/Delete`
  (`rulegroup_pusher.go`) and `NetworkPolicyController.pushSnapshotToNode`
  (`networkpolicy_controller.go`) all acquire across "read/mutate the cache for this node" plus
  "enqueue the corresponding push," so the two code paths can never interleave for the same node.
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md
git commit -m "docs: mark issue #4 (send-side snapshot/delta race) as fixed in migration spec"
```
