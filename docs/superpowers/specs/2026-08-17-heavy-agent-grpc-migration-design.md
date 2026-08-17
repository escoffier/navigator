# heavy-agent: TCP → gRPC migration design

## Overview

`cmd/daemon` (the Go host-agent binary in this repo) talks to `net-policy` (a
separate, native network-policy enforcement daemon running alongside it) over
two hand-rolled, length-prefixed TCP protocols on `127.0.0.1:9999` (control)
and `127.0.0.1:8888` (events), implemented in `cmd/daemon/pkg/heavy-agent`.

`net-policy`'s own repository (a from-scratch Rust rewrite, tracked separately
from the stale C++ copy vendored at `cmd/daemon/net-policy`) has already
completed its own migration to gRPC: it now exposes `NetPolicyControl` (port
`50051`) and `NetPolicyEvents` (port `50052`, server-streaming), and the
legacy raw-socket protocol was deleted outright in that repo's Phase 7 — no
dual-protocol period, no compatibility shim. `net-policy` also separately
removed WAF support entirely (its own deliberate, documented deviation): the
new proto has no WAF RPCs and no WAF event.

This spec covers bringing the Go side into line: replacing the TCP control
and event clients in `pkg/heavy-agent` and their consumers
(`pkg/microseg`, `status/server.go`, `main.go`'s wiring) with gRPC clients of
`NetPolicyControl`/`NetPolicyEvents`, generated from `net-policy`'s own
`.proto` files.

## Goals

- `pkg/microseg.PolicyClient` (`AddPolicy`/`DeletePolicy`/`AddContainer`/
  `DeleteContaier`) issues `AddPolicyRule`/`DeletePolicyRule`/`PodUp`/
  `PodDown` RPCs instead of hand-framed JSON over TCP.
- `status/server.go`'s five debug HTTP handlers (`dumpAgentConfig`,
  `SetAgentLogLevelReq`, `dumpAgentHeap`, `dumpAgentConn`, `reset`) issue
  `DumpConfig`/`SetLogLevel`/`DumpHeapProfile`/`DumpConnections`/
  `ResetConfig` RPCs.
- The microseg event pipeline (currently `heavyagent.EventProcessor`'s
  hand-rolled framing/dispatch loop, fed by the port-8888 socket) is replaced
  by a `SubscribeEvents` streaming RPC consumer that calls
  `microseg.NewHandler(...)`'s `Handle` directly on each `PolicyMatchEvent`.
- `main.go` dials the two new gRPC clients instead of the two
  `heavyagent.NewClient("127.0.0.1:9999"/"127.0.0.1:8888")` TCP clients, and
  wires them to `microseg`/`status` accordingly.
- The "resync all state after the peer comes back" behavior
  (`pod_controller.go`'s `ResynAllPods`, `policyrule_controller.go`'s
  `ReSyncAllPolicy`, both currently hung off `heavyagent.Client`'s
  `ReConnectCB`) is preserved under gRPC via connectivity-state watching (see
  below), with no change to either controller's own code.
- Hard cutover: the raw-socket protocol is not kept as a fallback or
  toggle for the parts of the codebase this spec touches.

## Non-Goals

- **`pkg/waf` is untouched.** It keeps embedding and calling the existing
  TCP `heavyagent.Client` (`Send`/`Receive`/`AddConnectCallback`), which
  therefore stays in `pkg/heavy-agent` exactly as it is today, unused by
  anything else. `pkg/waf` will simply fail at runtime against a `net-policy`
  build that no longer speaks that protocol — a known, accepted consequence,
  not something this spec fixes. `main.go` still constructs the old-style
  TCP client purely to hand it to `waf.NewWafClient(...)`; it is otherwise
  dead.
- **No changes to `cmd/daemon/net-policy`** (the stale vendored C++ copy) or
  the root `Makefile`'s `heavy-agent` build target. This spec assumes some
  running `net-rule` binary listening on `50051`/`50052`; how that binary
  gets built and deployed is out of scope.
- **No proto changes.** The three `.proto` files (`net_policy_common.proto`,
  `net_policy_control.proto`, `net_policy_events.proto`) are consumed as-is
  from `net-policy`'s repo, copied rather than modified (only a `go_package`
  option is added for Go codegen).
- **No change to policy validation/matching logic** (priority bounds, CIDR
  parsing, etc.) — that logic is server-side in `net-policy` already and
  untouched by this spec.
- **No change to `pkg/microseg`'s or `pkg/waf`'s Kubernetes-CRD-watching
  logic** — only the transport used to push the resulting state to the
  agent changes.

## Architecture

### Proto source and codegen

Copy `net-policy/proto/{net_policy_common,net_policy_control,net_policy_events}.proto`
into a new `cmd/daemon/pkg/heavy-agent/pb/` directory, adding a `go_package`
option to each (they currently have none, since `net-policy` only generates
Rust via `tonic-build`). This mirrors the repo's existing convention at
`pkg/streaming/pb/`: proto source and generated `.pb.go`/`_grpc.pb.go` files
committed side by side, plus a `gen.sh` wrapping
`protoc -I=. --go_out=. --go-grpc_out=require_unimplemented_servers=false:. *.proto`.
Keeping the proto bodies byte-identical to `net-policy`'s copy (aside from the
added `go_package` line) makes future re-syncs a diff against upstream, not a
rewrite.

### pkg/heavy-agent: two new gRPC clients alongside the untouched TCP client

- `ControlClient` — wraps the generated `NetPolicyControlClient`, dialed once
  at `127.0.0.1:50051` via `grpc.Dial` with
  `grpc.WithTransportCredentials(insecure.NewCredentials())`, matching the
  dial pattern already used in `pkg/streaming/streamfactory.go`. Exposes
  `AddReConnectionCallback` (same name/shape as today) for
  `pod_controller.go`/`policyrule_controller.go` to keep using unchanged.
- `EventsClient` — wraps `NetPolicyEventsClient`, dialed at
  `127.0.0.1:50052`. Exposes `Run(ctx context.Context, onEvent func(*pb.PolicyMatchEvent))`.
- The existing raw-socket `Client` type and its methods are left exactly as
  they are, for `pkg/waf`'s sake (see Non-Goals).
- `heavyagent.EventProcessor` (the hand-rolled length-prefixed
  framing/dispatch loop) is deleted; nothing outside `pkg/waf`'s dead path
  used it once the microseg event path moves to `EventsClient.Run`.

### Call-site changes

- **`pkg/microseg.PolicyClient`**: `AddPolicy`/`DeletePolicy` build an
  `AddPolicyRuleRequest`/`DeletePolicyRuleRequest` from the existing
  `PolicyRule`/`NodeRule` types — action/direction/protocol strings map to
  the corresponding proto enums (`PolicyAction`/`FlowDirection`/
  `L4Protocol`), `Address` maps to `AddressEndpoint`, ports map to
  `PortRange`, `crdv1alpha1.Http` maps to `HttpMatchRule`.
  `AddContainer`/`DeleteContaier` become `PodUp`/`PodDown` calls (`PodDown`
  only needs `pod_id`, so `DeleteContaier`'s `pid` argument is no longer sent
  — the interface signature can keep it for caller compatibility or drop it,
  decided at implementation time).
- **`status/server.go`**: each handler's request-building code changes to
  construct the matching typed proto request; the response is
  `json.Marshal`'d from the typed gRPC response before being written to the
  HTTP response. These are internal `/debug/agent/*` endpoints with no
  documented external consumer, so exact byte-for-byte JSON-shape parity
  with the old ad hoc format is not required.
- **`main.go`**: replaces the two `heavyagent.NewClient(...)` TCP dials with
  dialing `ControlClient` and `EventsClient`; passes `ControlClient` where
  `agentClient` was passed to `microseg.NewPolicyClient`/`status.NewServer`;
  still separately constructs the old TCP client to hand to
  `waf.NewWafClient(...)` (dead, per Non-Goals); replaces the
  `heavyagent.NewEventProcessor(...)` + `"microseg"`/`"waf"` handler
  registration with `EventsClient.Run(ctx, func(evt *pb.PolicyMatchEvent) { ... })`
  calling `microseg.NewHandler(...).Handle` directly — the `"waf"` handler
  registration is dropped from this wiring (there is no WAF event in the new
  stream; `pkg/waf`'s handler code itself is untouched, just no longer fed).

## Reconnect / resync semantics

Today, `pod_controller.go` and `policyrule_controller.go` register a
`ReConnectCB` that replays all pod/policy state whenever the TCP socket
reconnects, because `net-policy`'s daemon state is in-memory only — any time
the `net-policy` process restarts, the Go daemon must push all state again.
A raw TCP reconnect was a reasonable proxy for "the peer process restarted."

A `grpc.ClientConn` reconnects transparently at the transport level on
ordinary network blips, without necessarily surfacing that to application
code, so naively firing resync on every reconnect would over-fire relative
to today's behavior. Instead: `ControlClient` watches its `grpc.ClientConn`'s
connectivity state directly (`conn.GetState()` /
`conn.WaitForStateChange(ctx, state)` in a loop) and invokes registered
resync callbacks whenever the state transitions out of `TRANSIENT_FAILURE`
back to `READY` — the same "was down, is now back up" signal the old
`ReConnectCB` fired on, just sourced from gRPC's connectivity API instead of
`net.Dial` succeeding.

The event stream (`EventsClient.Run`) needs no separate resync hook: it
loops calling `SubscribeEvents`, dispatching every received `PolicyEvent` to
the handler, and on any `Recv()` error (including `io.EOF`) backs off briefly
and re-issues `SubscribeEvents`. It is one-way and stateless from the
client's perspective.

## Testing

- `pkg/heavy-agent`: new tests for `ControlClient`/`EventsClient` against an
  in-process gRPC server (via `google.golang.org/grpc/test/bufconn`,
  already available transitively through the existing `google.golang.org/grpc`
  dependency) implementing the two proto services — replacing
  `policy_client_test.go`'s current pattern of dialing a `/tmp/echo.socket`.
- `pkg/microseg/policy_client_test.go` is rewritten against the same
  `bufconn` fixture, asserting the right `AddPolicyRuleRequest`/
  `PodUpRequest`/etc. are sent for a given `PolicyRule`/`ContainerInfo`.
- `pkg/waf`, `cis`, `dp`, `rscan`, and everything else are untouched.

## Rollout

Direct cutover, no runtime toggle — consistent with `net-policy`'s own
migration history and this repo's existing conventions. This assumes the Go
daemon and a `net-policy` build exposing `NetPolicyControl`/`NetPolicyEvents`
on `50051`/`50052` are deployed together; no compatibility window with an
older `net-policy` build is provided.
