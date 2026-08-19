# Retry failed rule-group pushes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix [issue #5](https://github.com/escoffier/navigator/issues/5) — `syncPolicyRules`
logs a failed `Delete`/`Update` rule-group push and then swallows the error instead of returning
it, so `processNextItem`/`handleErr` never requeues the policy for retry. `grpcRuleGroupPusher.Delete`
deliberately keeps the cache entry when its push fails (so a retry can pick it up later) — but with
no retry ever triggered, that stale entry can sit in `pushedRuleGroupCache` indefinitely and later
get shipped to a reconnecting daemon via `pushSnapshotToNode`'s bootstrap snapshot, permanently
resurrecting a rule group that should have been deleted. This is the same user-visible symptom as
issue #4, reached through swallowed error handling rather than a race.

**Architecture:** `syncPolicyRules` already has the right shape for `Create` (it returns
immediately on a `Create` error); `Delete` and `Update` just need the same "the caller should know
this failed" signal, but without aborting the rest of the batch — every other issue #4/#2 fix in
this codebase already established the pattern of "keep going, then let the whole policy retry from
scratch" (e.g. `reconcileAllPolicies`'s poll-until-success loop) since these operations are
idempotent. So: accumulate the last `Delete`/`Update` error into a local variable while still
attempting every group, and return it at the end of `syncPolicyRules` — `syncPolicy`'s existing
error propagation to `processNextItem`/`handleErr` already requeues with backoff (up to
`maxRetries`) whenever `syncPolicyRules` returns non-nil, so no other code changes anywhere else are
needed.

**Tech Stack:** Go. No new dependencies — plain local error variable, no `errors.Join`/multierror
(this file already imports a package named `errors` — `k8s.io/apimachinery/pkg/api/errors` — so
introducing the stdlib `errors` package under that same name would collide; not worth an import
alias just for this).

**Spec:** `docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md` (see its
"Known limitations" section, fourth bullet) and
[github.com/escoffier/navigator issue #5](https://github.com/escoffier/navigator/issues/5).

## Global Constraints

- Only affects the `MICROSEG_GRPC_ENABLED=true` path in practice — `k8sRuleGroupPusher`'s
  Create/Update/Delete calls the k8s apiserver directly and its own errors are unaffected by this
  change's shape (this fix touches `syncPolicyRules`, which is shared by both pushers, but the
  behavior change — "a push failure now makes the policy retry" — only has a materially different
  outcome on the gRPC path, since the CRD path's writes are durable and its own retry semantics via
  the k8s client are unchanged).
- Do not change `Create`'s existing immediate-return-on-error behavior — only `Delete`'s loop and
  `Update`'s single call need the fix.
- Every rule group in the delete/update batch must still be attempted even after an earlier one in
  the same call fails — do not short-circuit the loops.
- Follow existing code style: plain accumulator variable (matches how the rest of this file handles
  errors — no aggregation libraries), existing `logging.Get().Error().Err(err)...` log calls stay as
  they are.
- `.golangci.yml`: `lll` (150 cols), `cyclop` max-complexity 20.

---

## Task 1: Return accumulated push errors from `syncPolicyRules`

**Files:**
- Modify: `cmd/clustermanager/pkg/microseg/networkpolicy_controller.go`
- Test: `cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go`

**Interfaces:** None new — `syncPolicyRules(policy string, rules map[string]*crdv1alpha1.NetworkPolicyRuleGroup) error`'s signature is unchanged; only what it returns in the failure case changes.

- [ ] **Step 1: Write the failing tests**

Add `"errors"` to the stdlib import group in
`cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go` — find:

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

Replace with:

```go
import (
	"context"
	"errors"
	"flag"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
```

Then add these two tests near the existing `Test_syncPolicyRules_UsesInjectedPusher` (same package,
reuses the existing `fakeRuleGroupStream` type from `rulegroup_pusher_test.go` and
`grpcRuleGroupPusher`/`newPushedRuleGroupCache` already used by that test):

```go
func Test_syncPolicyRules_ReturnsErrorWhenDeleteFails(t *testing.T) {
	cache := newPushedRuleGroupCache()
	cache.Set(&crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "policy-node1", Labels: map[string]string{"kubernetes.io/networkpolicy-name": "policy"}},
		Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{Policy: "policy", NodeName: "node1"},
	})
	stream := &fakeRuleGroupStream{err: errors.New("push failed")}
	npc := &NetworkPolicyController{
		ruleGroupLister: cache,
		ruleGroupPusher: &grpcRuleGroupPusher{cache: cache, stream: stream},
	}

	// No rule groups desired anymore, so the existing "policy-node1" entry
	// should be deleted — the delete push fails via the fake stream's err.
	rules := map[string]*crdv1alpha1.NetworkPolicyRuleGroup{}

	if err := npc.syncPolicyRules("policy", rules); err == nil {
		t.Fatal("syncPolicyRules: want error when a delete push fails, got nil")
	}
	// The cache entry must still be there — grpcRuleGroupPusher.Delete keeps
	// it on push failure (already tested at the pusher level); this test is
	// about syncPolicyRules surfacing that failure, not re-testing Delete.
	if _, err := cache.Get("policy-node1"); err != nil {
		t.Fatalf("cache entry removed despite failed delete push: %v", err)
	}
}

func Test_syncPolicyRules_ReturnsErrorWhenUpdateFails(t *testing.T) {
	cache := newPushedRuleGroupCache()
	cache.Set(&crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "policy-node1", Labels: map[string]string{"kubernetes.io/networkpolicy-name": "policy"}},
		Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{Policy: "policy", NodeName: "node1"},
	})
	stream := &fakeRuleGroupStream{err: errors.New("push failed")}
	npc := &NetworkPolicyController{
		ruleGroupLister: cache,
		ruleGroupPusher: &grpcRuleGroupPusher{cache: cache, stream: stream},
	}

	// Same name still desired -> syncPolicyRules takes the Update path
	// (ruleGroupLister.Get finds the existing entry), and that push fails.
	rules := map[string]*crdv1alpha1.NetworkPolicyRuleGroup{
		"node1": {
			ObjectMeta: v1.ObjectMeta{Name: "policy-node1", Labels: map[string]string{"kubernetes.io/networkpolicy-name": "policy"}},
			Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{Policy: "policy", NodeName: "node1"},
		},
	}

	if err := npc.syncPolicyRules("policy", rules); err == nil {
		t.Fatal("syncPolicyRules: want error when an update push fails, got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_syncPolicyRules_ReturnsErrorWhen -v`
Expected: FAIL — both tests currently get `err == nil` back from `syncPolicyRules` despite the
push failing (the log-and-swallow bug), so both `t.Fatal` calls fire.

- [ ] **Step 3: Accumulate and return push errors**

In `cmd/clustermanager/pkg/microseg/networkpolicy_controller.go`, find:

```go
	deletingRuleGroups := curRuleGroupNames.Difference(desiredRuleGroupNames)
	logging.Get().Info().Msgf("deletingRuleGroups %v", deletingRuleGroups.List())
	for name := range deletingRuleGroups {
		err := npc.ruleGroupPusher.Delete(context.Background(), name)
		if err != nil {
			logging.Get().Error().Err(err).Msgf("delete rule group %s", name)
		}
	}

	for _, r := range rules {
		curRule, err := npc.ruleGroupLister.Get(r.Name)
		if err != nil {
			if errors.IsNotFound(err) {
				err = npc.ruleGroupPusher.Create(context.TODO(), r)
				npc.updatePolicyRuleStatus(err, r.Spec.Rules)
				if err != nil {
					return err
				}
				continue
			}
			npc.updatePolicyRuleStatus(err, r.Spec.Rules)
			return err
		}
		err = npc.ruleGroupPusher.Update(context.TODO(), curRule, r)
		if err != nil {
			logging.Get().Error().Err(err).Msgf("update rule group %s", r.Name)
		}
	}
	// npc.ruleGroupMap[policy] = ruleGroupNames
	return nil
}
```

Replace with:

```go
	deletingRuleGroups := curRuleGroupNames.Difference(desiredRuleGroupNames)
	logging.Get().Info().Msgf("deletingRuleGroups %v", deletingRuleGroups.List())
	// pushErr accumulates delete/update push failures so the policy still
	// gets retried (via processNextItem/handleErr's requeue-with-backoff)
	// instead of silently leaving a stale pushedRuleGroupCache entry that
	// can resurrect on a later daemon reconnect (issue #5). Every group is
	// still attempted even after an earlier failure in this same call,
	// matching the existing "log and continue" behavior for the ones that
	// do succeed.
	var pushErr error
	for name := range deletingRuleGroups {
		err := npc.ruleGroupPusher.Delete(context.Background(), name)
		if err != nil {
			logging.Get().Error().Err(err).Msgf("delete rule group %s", name)
			pushErr = err
		}
	}

	for _, r := range rules {
		curRule, err := npc.ruleGroupLister.Get(r.Name)
		if err != nil {
			if errors.IsNotFound(err) {
				err = npc.ruleGroupPusher.Create(context.TODO(), r)
				npc.updatePolicyRuleStatus(err, r.Spec.Rules)
				if err != nil {
					return err
				}
				continue
			}
			npc.updatePolicyRuleStatus(err, r.Spec.Rules)
			return err
		}
		err = npc.ruleGroupPusher.Update(context.TODO(), curRule, r)
		if err != nil {
			logging.Get().Error().Err(err).Msgf("update rule group %s", r.Name)
			pushErr = err
		}
	}
	// npc.ruleGroupMap[policy] = ruleGroupNames
	return pushErr
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_syncPolicyRules -v`
Expected: PASS — both new tests, plus the pre-existing `Test_syncPolicyRules_UsesInjectedPusher`
(confirms the success path still returns `nil`, unaffected by this change).

Run the broader scoped set this codebase's `MICROSEG_GRPC_ENABLED` path touches, to catch fallout:
`go test ./cmd/clustermanager/pkg/microseg/... -run 'Test_syncPolicyRules|Test_grpcRuleGroupPusher|Test_pushedRuleGroupCache|Test_RegisterOnConnect|Test_MarkWarmAndSync|Test_reconcileAllPolicies|Test_pushSnapshotToNode' -v`
Expected: PASS (all of them).

**Known pre-existing, out-of-scope failures in this package (do not fix, do not treat as
regressions):** `TestNetworkPolicyController_caculatePolicy`, `TestPolicyIndex`,
`TestNetworkPolicyController_caculateAddressMap`, `TestNetworkPolicyController_caculateNodeRules`
(pointer-vs-nil `PodReference` mismatches predating all of this work), `TestCreateCRD` (needs a
live envtest apiserver), `Test_getServicePort` (pre-existing panic).

- [ ] **Step 5: Commit**

```bash
git add cmd/clustermanager/pkg/microseg/networkpolicy_controller.go cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go
git commit -m "fix(clustermanager/microseg): retry policy sync when a rule-group push fails"
```

---

## Task 2: Document the fix in the migration spec

**Files:**
- Modify: `docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md`

**Interfaces:** None — documentation only.

- [ ] **Step 1: Update the "Known limitations" intro and the issue #5 bullet**

In `docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md`, find:

```
### Known limitations (surfaced across three rounds of final whole-branch review)

Three gaps were found here, all architectural rather than implementation bugs — all three are now
fixed. A fourth, narrower gap (error handling, not architectural) was found by the third review;
it's tracked separately below.
```

Replace with:

```
### Known limitations (surfaced across three rounds of final whole-branch review)

Four gaps have been found here — all four are now fixed.
```

Then find the final bullet (issue #5):

```
- **Failed DELETE push leaves a stale cache entry that resurrects on daemon reconnect** (tracked
  as [#5](https://github.com/escoffier/navigator/issues/5)). `grpcRuleGroupPusher.Delete`
  deliberately keeps the cache entry when the push itself fails (so a later attempt can retry), but
  `syncPolicyRules`'s delete loop only logs that error — it never returns it, so the policy is
  never requeued with backoff. The most likely failure is the target daemon being disconnected,
  which is exactly the reconnect scenario issue #4 concerned — so a deleted rule group can still
  resurrect on reconnect through this path, via swallowed error handling rather than a race. Self-
  heals only via the 8-hour informer resync. Needs `syncPolicyRules` to aggregate and return delete
  errors so `handleErr` requeues the policy.
```

Replace with:

```
- **Failed DELETE push leaves a stale cache entry that resurrects on daemon reconnect** (tracked
  as [#5](https://github.com/escoffier/navigator/issues/5), fixed). `grpcRuleGroupPusher.Delete`
  deliberately keeps the cache entry when the push itself fails (so a later attempt can retry), but
  `syncPolicyRules`'s delete loop used to only log that error — never return it, so the policy was
  never requeued with backoff. The most likely failure is the target daemon being disconnected,
  which is exactly the reconnect scenario issue #4 concerned — so a deleted rule group could still
  resurrect on reconnect through this path, via swallowed error handling rather than a race. Self-
  healed only via the 8-hour informer resync. Fixed by having `syncPolicyRules` accumulate any
  `Delete`/`Update` push failure (while still attempting every other rule group in the same call)
  and return it, so `processNextItem`/`handleErr`'s existing requeue-with-backoff picks the policy
  back up instead of the error being silently dropped after logging.
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md
git commit -m "docs: mark issue #5 (swallowed delete/update push errors) as fixed in migration spec"
```
