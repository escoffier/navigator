# Migrate microseg `NetworkPolicyRuleGroup` sync (clustermanager ↔ daemon) to gRPC

Date: 2026-08-18

## Problem

Today clustermanager computes per-node `NetworkPolicyRuleGroup` objects from `ClusterNetworkPolicy`
and writes them as a Kubernetes CRD (`cmd/clustermanager/pkg/microseg/networkpolicy_controller.go`).
Daemon watches that CRD via a per-node-filtered k8s informer
(`cmd/daemon/pkg/microseg/policyrule_controller.go`) and pushes the resulting rules to the local
net-policy engine over gRPC (`cmd/daemon/pkg/microseg/policy_client.go`, already migrated in the
"heavy-agent gRPC migration" — see `2026-08-17-heavy-agent-grpc-migration-design.md`).

The k8s apiserver is being used as a bespoke sync transport between two specific processes
(clustermanager and daemon) for data no third component consumes (confirmed: only these two
packages reference `NetworkPolicyRuleGroup`). This spec replaces that CRD-watch transport with a
direct push over the gRPC channel these two processes already share.

## Existing infrastructure this builds on

`cmd/daemon/main.go` already opens a persistent bidirectional gRPC stream to clustermanager via
`pkg/streaming` (package `rpcstream`), dialing `CLUSTER_MANAGER_GRPC_ADDR`. This channel already
carries clustermanager→daemon pushes for other concerns (`ComplianceScanReq`, `NodeLoadReq`),
addressed per-node via a flat string key `"<nodeName>-daemon"`. Clustermanager runs the
corresponding in-cluster gRPC server on `:19090` (`cmd/clustermanager/cmd/server.go`).

Unlike `ComplianceScanReq`/`NodeLoadReq` (which proxy console→clustermanager→daemon), rule-group
data originates at clustermanager itself (it already watches `ClusterNetworkPolicy`), so pushes
go directly from clustermanager down to daemon with no console hop.

## Non-goals

- No change to how clustermanager computes rule groups from `ClusterNetworkPolicy`
  (`syncPolicyRules`/`generateRules`/`caculatePolicy*` logic is reused as-is; only the sink changes).
- No change to daemon's local net-policy push path (`policy_client.go`, `AddPolicy`/`DeletePolicy`
  gRPC calls to the embedded net-policy engine) or its `checkSync`/`DumpConfig` reconciliation loop.
- No change to the microseg event-reporting path (daemon → clustermanager HTTP POST of match
  events, `cmd/daemon/pkg/microseg/handle.go`) — out of scope, unrelated transport.
- Not addressing WAF (already dead/unmigrated, tracked separately, see prior spec).
- No support for clustermanager HA/multi-replica — confirmed single instance per cluster.

## Design

### Sync model: incremental CRUD + bootstrap-on-connect

- **Incremental**: clustermanager keeps computing per-rule-group Create/Update/Delete diffs exactly
  as today, but instead of `clientset.NetworkPolicyRuleGroups().Create/Update/Delete()`, it calls a
  new `PushRuleGroup(ctx, nodeKey, messageType, payload)` on the in-cluster stream, targeting
  `nodeKey = fmt.Sprintf("%s-daemon", nodeName)` — the same addressing convention `ComplianceScanReq`/
  `NodeLoadReq` already use.
- **Bootstrap-on-connect**: the stream framework's client sends a `Register` message on connect, but
  `messageStreamServer.SendMessage` (`pkg/streaming/streamfactory.go`) consumes that first message
  directly via `stream.Recv()` before the handler-dispatch loop starts, so it can't be intercepted
  via the normal `AddHandler` mechanism. Instead, this spec adds a new `OnConnect` extension point to
  the streaming framework itself — a callback fired with the connecting peer's node key right after
  its stream is registered. Clustermanager registers one that looks up all rule groups currently
  computed for that node and pushes them as one `NetworkPolicyRuleGroupSyncReq` snapshot. Note:
  `cmd/clustermanager/pkg/microseg/store.go`'s `NewRuleStore`/`NewPolicyStore` turned out to be
  unused dead code (confirmed via repo-wide grep) — there is no existing in-memory store to reuse
  here, so this spec adds a small new one (`pushedRuleGroupCache`) purpose-built for this lookup,
  fed by the same Create/Update/Delete pushes described above. This replaces the implicit full-List
  a k8s informer gets on startup/reconnect, so daemon always converges to correct state after a
  restart or network blip without needing k8s as an intermediary.
- Daemon's local net-policy reconciliation (`checkSync`/`ReSyncAllPolicy`/`DumpConfig`) is unchanged;
  it already reconciles against "whatever daemon currently considers desired state" — that state now
  comes from the stream-fed cache instead of the informer lister.

### Proto design

New file `pkg/streaming/pb/microseg.proto` (sibling to `compliance.proto`, added to `gen.sh`).
Fresh, microseg-specific message types (not reusing the existing-but-unused `PolicyRule`/`IPBlock`
family already in `cluster.proto`, to avoid coupling to a possibly-stale schema) mapped field-for-
field onto the vendored CRD type
(`scm.tensorsecurity.cn/tensorsecurity-rd/api@.../pkg/apis/microsegmentation.security.io/v1alpha1/types.go`,
`NetworkPolicyRuleGroupSpec`/`NodeRule`/`Address`/`IPBlock`/`NetworkPolicyPort`/`Http`):

```proto
syntax = "proto3";
package pb;
option go_package = "./;pb";

message MicrosegAddress {
    string IP = 1;
    string PodNamespace = 2;
    string PodName = 3;
}

message MicrosegIPBlock {
    string CIDR = 1;
}

message MicrosegPort {
    string Protocol = 1;   // TCP/UDP/ICMP, mirrors CRD's *Protocol
    string Port = 2;       // numeric or named, mirrors CRD's *intstr.IntOrString
    int32 EndPort = 3;
}

message MicrosegHttp {
    string Method = 1;
    string Path = 2;
    string Host = 3;
}

message MicrosegNodeRule {
    string Name = 1;
    int32 Priority = 2;
    string Protocol = 3;
    string Direction = 4;
    string Action = 5;
    repeated MicrosegPort Ports = 6;
    repeated MicrosegAddress ToAddresses = 7;
    repeated MicrosegIPBlock ToIPBlock = 8;
    repeated MicrosegAddress FromAddress = 9;
    repeated MicrosegIPBlock FromIPBlock = 10;
    MicrosegHttp Http = 11;
}

message NetworkPolicyRuleGroupPayload {
    string Name = 1;       // rule group identity (== CRD ObjectMeta.Name today)
    string Policy = 2;     // source ClusterNetworkPolicy name
    string NodeName = 3;
    repeated MicrosegNodeRule Rules = 4;
}

message NetworkPolicyRuleGroupReq {
    NetworkPolicyRuleGroupPayload RuleGroup = 1;   // single CRUD event
}

message NetworkPolicyRuleGroupSyncReq {
    repeated NetworkPolicyRuleGroupPayload RuleGroups = 1;   // bootstrap-on-connect snapshot
}

message NetworkPolicyRuleGroupResp {
    bool Success = 1;
    string Error = 2;
}
```

### Clustermanager-side changes

- `networkpolicy_controller.go`: `syncPolicyRules`/`generateRules`/`caculatePolicy*` computation is
  unchanged. The sink at the Create/Update/Delete call sites (currently
  `clietset.NetworkPolicyRuleGroups().Create/Update/Delete()`) is replaced with
  `inClusterStream.PushRuleGroup(ctx, nodeKey, MessageType, payload)`.
- `pkg/streaming/client.go`: add `PushRuleGroup` to `MessageStreamClient`, same shape as
  `PushComplianceScan`, wrapping `NetworkPolicyRuleGroupReq` with `ack=false` (fire-and-forget,
  matching today's un-acked CRD write).
- `pkg/streaming/streamfactory.go`: add an `OnConnect(f func(nodeKey string))` method to
  `MessageStream`, fired from `messageStreamServer.SendMessage` right after a connecting peer's
  stream is registered (see the corrected bootstrap-on-connect note above).
  `cmd/clustermanager/cmd/server.go`/`networkpolicy_controller.go`: register a callback via
  `OnConnect` that, on a daemon (re)connecting under a given node key, looks up that node's
  currently computed rule groups from a new in-memory cache (`pushedRuleGroupCache`, populated by
  the same Create/Update/Delete pushes) and pushes a `NetworkPolicyRuleGroupSyncReq` snapshot. This
  cache is in-memory only, consistent with the single-instance/no-shared-store assumption.
- The CRD write path and its clientset wiring are removed once the rollout flag (below) is flipped
  and verified.

### Daemon-side changes

- `main.go`: when `MICROSEG_GRPC_ENABLED=true`, register
  `rpcStream.AddHandler(&pb.NetworkPolicyRuleGroupReq{}, &microseg.RuleGroupStreamHandler{...})`
  and a handler/callback for `NetworkPolicyRuleGroupSyncReq` (bulk-replaces local desired-state
  cache), instead of building the `externalversions` informer factory and
  `NewRuleGroupController(clientset.TensorClientset, tensorFactory, ...)`.
- New proto→local-struct mapping mirrors the existing `buildPolicyRuleMessage*` functions in
  `policyrule_controller.go` — same output shape (`PolicyRule`/`NodeRule`), sourced from
  `pb.NetworkPolicyRuleGroupPayload` instead of the CRD's `NetworkPolicyRuleGroupSpec`.
  `OnCreate`/`OnUpdate`/`OnDelete` on the new handler call into the same `polCli.AddPolicy`/
  `DeletePolicy` path the informer callbacks call today.
- `checkSync`/`ReSyncAllPolicy`/`DumpConfig` reconciliation is untouched.
- The `tensorFactory`/`externalversions`/node-name-label-selector wiring (`main.go:432-436`) is
  removed once the flag flip is complete.

### Rollout

- New env flag `MICROSEG_GRPC_ENABLED`, set consistently on **both** clustermanager and daemon for
  a given cluster (they must move in lockstep — a stream-only daemon can't consume CRD writes and
  vice versa). Off ⇒ today's CRD/informer path, unchanged. On ⇒ stream path only, no CRD write (no
  hybrid/dual-write state).
- Old CRD/informer code stays in the tree, dormant, behind the flag until verified on a real
  cluster, then removed in a follow-up cleanup commit — mirrors the heavy-agent migration's
  wire-then-verify-then-cleanup commit sequence.

### Testing

- Unit tests for the new proto↔local-struct mapping (mirrors `proto_mapping_test.go`).
- Unit tests for the new stream handler's `OnCreate`/`OnUpdate`/`OnDelete`/sync-snapshot behavior —
  fills an existing gap (`policyrule_controller.go` currently has no tests at all).
- Unit tests for clustermanager's new `PushRuleGroup` call sites and the `Register`-triggered
  snapshot handler.
- No e2e harness exists for this path; rely on unit tests plus manual verification (`doc/UseTest.md`
  convention) before flipping the flag on a real cluster.

### Known limitations (surfaced by the final whole-branch review, not fixed in this pass)

Two gaps were found that are architectural rather than implementation bugs — both are documented
here as explicit blockers for production rollout, to be addressed in a follow-up design pass
rather than folded into this migration's fix wave:

- **Non-durable pushed-state cache loses DELETEs across a clustermanager restart.** Today's CRD
  write makes k8s the durable "current state" `syncPolicyRules` diffs against; `pushedRuleGroupCache`
  is in-memory only. If a node drops out of a policy's scope while clustermanager is down, the
  first reconcile after restart sees an empty "current" set and has nothing to diff the removal
  against, so no DELETE is ever sent — that node's daemon keeps enforcing the stale rule group
  indefinitely. A correct fix needs a "warm" gate: only start answering `OnConnect` bootstrap
  requests (including legitimately-empty ones) after clustermanager has completed one full
  reconcile pass over every `ClusterNetworkPolicy`, and push corrected snapshots to
  already-connected daemons at that warm transition — sending real snapshots before warm risks
  transiently wiping correct daemon state with an incomplete view.
- **`pkg/streaming`'s per-message dispatch (`go func(){ handler.OnX(...) }()` in `stream.go`) does
  not preserve message ordering**, and this migration is the first user of that framework to put
  ordered state replication (CREATE/UPDATE/DELETE for the same rule group) on it — every prior use
  (compliance scans, node load queries) was idempotent one-shot RPCs where order didn't matter. Two
  `UPDATE`s for the same rule group in quick succession can be applied out of order, and there is no
  self-healing: `checkSync` only warns on divergence, it never re-syncs. Needs either synchronous
  per-rule-group-name dispatch, a serializing worker keyed by rule-group name, or a monotonic
  generation/resourceVersion carried in the payload so stale messages can be dropped on receipt.
