# heavy-agent TCP → gRPC Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `cmd/daemon`'s hand-rolled, length-prefixed TCP protocol to `net-policy` (ports 9999/8888) with gRPC clients of `net-policy`'s `NetPolicyControl` (port 50051) and `NetPolicyEvents` (port 50052) services, for every call site except `pkg/waf` (explicitly out of scope, stays on the old TCP client).

**Architecture:** Vendor `net-policy`'s three `.proto` files into `cmd/daemon/pkg/heavy-agent/pb`, generate Go/gRPC stubs, and add two new client types (`ControlClient`, `EventsClient`) to `pkg/heavy-agent` alongside the existing (untouched) TCP `Client`. `pkg/microseg` and `status/server.go` are rewritten to call the new clients; `main.go` rewires construction; the old `EventProcessor` framing/dispatch loop is deleted.

**Tech Stack:** Go, `google.golang.org/grpc` v1.56.3, `google.golang.org/protobuf` v1.30.0, `protoc`, `protoc-gen-go`/`protoc-gen-go-grpc`, `google.golang.org/grpc/test/bufconn` for tests.

## Global Constraints

- Module path: `gitlab.com/piccolo_su/vegeta`. All new/edited files live under `cmd/daemon/`.
- Hard cutover, no runtime toggle — per `docs/superpowers/specs/2026-08-17-heavy-agent-grpc-migration-design.md`.
- `pkg/waf`'s own files are not modified in this plan (its `*heavyagent.Client` dependency stays available; only how `main.go` constructs/wires it changes).
- No changes to `net-policy` (neither the vendored C++ copy at `cmd/daemon/net-policy` nor the separate Rust repo) or to policy validation logic.
- Every new Go file must compile under `CGO_ENABLED=0` — the packages touched here (`pkg/heavy-agent`, `pkg/microseg`, `status`, `main.go`) contain no cgo.
- Enum/int wire-code mappings (Action/Direction/Protocol) must exactly match the ground-truth values below — verified directly against `cmd/daemon/net-policy/net-policy.cpp`/`utils.h`/`net-policy.h` (the sender's C++ source) and `cmd/clustermanager/pkg/clusterserver/filter.go` (the consumer's Go source):
  - Action: `"Allow"`/`"Log"` → `1` (Allow); `"Alert"` → `2` (Alert); anything else (incl. `"Deny"`) → `0` (Deny).
  - Direction: `"ingress"` → `0` (Ingress); anything else → `1` (Egress).
  - Protocol: `"TCP"` → `6`; `"UDP"` → `17`; `"ICMP"` → `1`; anything else (incl. `""`) → `0`.
  - New proto enums (`pb.PolicyAction`, `pb.FlowDirection`, `pb.L4Protocol`) all reserve `0` for `*_UNSPECIFIED` and are numbered one higher than the legacy C++ ordinals — never cast a proto enum directly to the legacy int code.

---

### Task 1: Vendor `net-policy`'s proto files and generate Go/gRPC stubs

**Files:**
- Create: `cmd/daemon/pkg/heavy-agent/pb/net_policy_common.proto`
- Create: `cmd/daemon/pkg/heavy-agent/pb/net_policy_control.proto`
- Create: `cmd/daemon/pkg/heavy-agent/pb/net_policy_events.proto`
- Create: `cmd/daemon/pkg/heavy-agent/pb/gen.sh`
- Create (generated, via `gen.sh`): `cmd/daemon/pkg/heavy-agent/pb/net_policy_common.pb.go`, `net_policy_control.pb.go`, `net_policy_control_grpc.pb.go`, `net_policy_events.pb.go`, `net_policy_events_grpc.pb.go`

**Interfaces:**
- Produces: Go package `gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb` (import name `pb`), exporting `NetPolicyControlClient`/`NewNetPolicyControlClient`, `NetPolicyEventsClient`/`NewNetPolicyEventsClient`, and every message/enum type referenced in later tasks (`AddPolicyRuleRequest`, `DeletePolicyRuleRequest`, `PodUpRequest`, `PodDownRequest`, `StatusResponse`, `DumpConfigRequest`, `DumpConfigResponse`, `PolicyRuleConfigEntry`, `DumpHeapProfileRequest`, `DumpConnectionsRequest`, `DumpConnectionsResponse`, `ResetConfigRequest`, `SetLogLevelRequest`, `PolicyRuleSpec`, `PortRange`, `HttpMatchRule`, `AddressEndpoint`, `PolicyAction`/`FlowDirection`/`L4Protocol` enums and their `_UNSPECIFIED`/named constants, `SubscribeEventsRequest`, `PolicyEvent`, `PolicyMatchEvent`).

This is source-copied from `/Users/robbieqiu/workspace/net-policy/proto/*.proto`, unmodified except for an added `go_package` option (that repo has no Go codegen of its own, so it has none today).

- [ ] **Step 1: Create the pb directory and copy `net_policy_common.proto`**

```protobuf
syntax = "proto3";
package netpolicy.v1;

option go_package = "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb;pb";

// mirrors FlowDir, net-policy.h:95-96
enum FlowDirection {
  FLOW_DIRECTION_UNSPECIFIED = 0;
  FLOW_DIRECTION_INGRESS     = 1;
  FLOW_DIRECTION_EGRESS      = 2;
}

// mirrors NetPolicyRule (Deny/Allow/Mark), net-policy.cpp:1373-1379 ("Allow"/"Log" -> allow, "Alert" -> mark)
enum PolicyAction {
  POLICY_ACTION_UNSPECIFIED = 0;
  POLICY_ACTION_DENY        = 1;
  POLICY_ACTION_ALLOW       = 2;
  POLICY_ACTION_ALERT       = 3;
}

enum L4Protocol {
  L4_PROTOCOL_UNSPECIFIED = 0;
  L4_PROTOCOL_TCP         = 1;
  L4_PROTOCOL_UDP         = 2;
  L4_PROTOCOL_ICMP        = 3;
}

// mirrors RULE_PORT / RulePort, net-policy.h:194-200; end_port == 0 means "same as port"
message PortRange {
  uint32 port     = 1;
  uint32 end_port = 2;
}

// mirrors HTTP_RULE_INFO's host/method/path fields, net-policy.h:209-216
message HttpMatchRule {
  string host   = 1;
  string method = 2;
  string path   = 3;
}

// mirrors one element of rules[].from_addresses[]/to_addresses[], net-policy.cpp:1519-1544, 1578-1602.
message AddressEndpoint {
  string ip     = 1;
  uint64 pod_id = 2;
}
```

- [ ] **Step 2: Copy `net_policy_control.proto`**

```protobuf
syntax = "proto3";
package netpolicy.v1;

option go_package = "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb;pb";

import "net_policy_common.proto";

service NetPolicyControl {
  rpc PodUp(PodUpRequest)                       returns (StatusResponse);
  rpc PodDown(PodDownRequest)                   returns (StatusResponse);
  rpc AddPolicyRule(AddPolicyRuleRequest)       returns (StatusResponse);
  rpc DeletePolicyRule(DeletePolicyRuleRequest) returns (StatusResponse);
  rpc DumpHeapProfile(DumpHeapProfileRequest)   returns (StatusResponse);
  rpc DumpConfig(DumpConfigRequest)             returns (DumpConfigResponse);
  rpc DumpConnections(DumpConnectionsRequest)   returns (DumpConnectionsResponse);
  rpc ResetConfig(ResetConfigRequest)           returns (StatusResponse);
  rpc UpdateNodeConfig(UpdateNodeConfigRequest) returns (StatusResponse);
  rpc SetLogLevel(SetLogLevelRequest)           returns (StatusResponse);
}

message StatusResponse {
  int32  status = 1;
  string uuid   = 2;
}

message PodUpRequest {
  int32  pid    = 1;
  uint64 pod_id = 2;
}
message PodDownRequest {
  uint64 pod_id = 1;
}

message PolicyRuleSpec {
  PolicyAction  action      = 1;
  FlowDirection direction   = 2;
  L4Protocol    protocol    = 3;
  repeated HttpMatchRule   http_rules     = 4;
  repeated AddressEndpoint from_addresses = 5;
  repeated AddressEndpoint to_addresses   = 6;
  repeated PortRange       ports          = 7;
  int32 priority = 8;
}
message AddPolicyRuleRequest {
  string policy_name = 1;
  repeated PolicyRuleSpec rules = 2;
}
message DeletePolicyRuleRequest {
  string policy_name = 1;
}

message DumpHeapProfileRequest {
  bool enable = 1;
}

message DumpConfigRequest {
  string policy_name = 1;
}

message PolicyRuleConfigEntry {
  string policy_name  = 1;
  int32  priority      = 2;
  string direction     = 3;
  string action        = 4;
  string protocol      = 5;
  int32  protocol_int  = 6;
  string from_address  = 7;
  string to_address    = 8;
}
message ContainerInfo {
  int32  pid    = 1;
  uint64 pod_id = 2;
}
message DumpConfigResponse {
  repeated PolicyRuleConfigEntry inbound_rules  = 1;
  repeated PolicyRuleConfigEntry outbound_rules = 2;
  repeated ContainerInfo containers = 3;
  int64 tcp_connections = 4;
}

message DumpConnectionsRequest {
  int32 limit = 1;
}
message DumpConnectionsResponse {
  int64 total = 1;
  repeated string items = 2;
}

message ResetConfigRequest {}

message UpdateNodeConfigRequest {
  enum Action {
    ACTION_UNSPECIFIED = 0;
    ACTION_ADD          = 1;
    ACTION_DELETE       = 2;
  }
  Action action = 1;
  repeated string node_ips = 2;
}

message SetLogLevelRequest {
  int32 level = 1;
}
```

- [ ] **Step 3: Copy `net_policy_events.proto`**

```protobuf
syntax = "proto3";
package netpolicy.v1;

option go_package = "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb;pb";

import "net_policy_common.proto";

service NetPolicyEvents {
  rpc SubscribeEvents(SubscribeEventsRequest) returns (stream PolicyEvent);
}

message SubscribeEventsRequest {
  string client_id = 1;
}

message PolicyEvent {
  oneof event {
    PolicyMatchEvent policy_match = 1;
  }
}

message PolicyMatchEvent {
  L4Protocol    protocol    = 1;
  PolicyAction  action      = 2;
  FlowDirection direction   = 3;
  uint32 src_port    = 4;
  uint32 dst_port    = 5;
  string src_ip      = 6;
  string dst_ip      = 7;
  string policy_name = 8;
}
```

Note: the import lines above use bare filenames (`import "net_policy_common.proto";`), not the `proto/`-prefixed paths from `net-policy`'s own repo — that prefix only made sense relative to `net-policy`'s own repo root, and `protoc -I=.` here will resolve bare filenames within `pb/` directly.

- [ ] **Step 4: Create `gen.sh`**

```bash
#! /bin/bash

protoc -I=. --go_out=. --go-grpc_out=require_unimplemented_servers=false:. \
    net_policy_common.proto net_policy_control.proto net_policy_events.proto
```

(mirrors `pkg/streaming/pb/gen.sh`'s existing invocation style in this repo.)

- [ ] **Step 5: Install matching protoc plugins and run codegen**

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.30.0
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0
cd cmd/daemon/pkg/heavy-agent/pb && ./gen.sh
```

Expected: five `.pb.go`/`_grpc.pb.go` files appear alongside the three `.proto` files, each headed `// Code generated by protoc-gen-go...` / `// Code generated by protoc-gen-go-grpc...` (matching the style already in `pkg/streaming/pb/cluster.pb.go`/`cluster_grpc.pb.go`).

- [ ] **Step 6: Verify the generated package builds**

Run: `go build ./cmd/daemon/pkg/heavy-agent/pb/...`
Expected: succeeds with no output.

- [ ] **Step 7: Commit**

```bash
git add cmd/daemon/pkg/heavy-agent/pb/
git commit -m "feat(daemon): vendor net-policy proto files and generate gRPC stubs"
```

---

### Task 2: `ControlClient` in pkg/heavy-agent

**Files:**
- Create: `cmd/daemon/pkg/heavy-agent/control_client.go`
- Test: `cmd/daemon/pkg/heavy-agent/control_client_test.go`

**Interfaces:**
- Consumes: `pb.NetPolicyControlClient`, `pb.NewNetPolicyControlClient(grpc.ClientConnInterface) pb.NetPolicyControlClient` (Task 1). The existing `ReConnectCB func() error` type, already defined in `cmd/daemon/pkg/heavy-agent/client.go` (unchanged).
- Produces: `type ControlClient struct { pb.NetPolicyControlClient; ... }`, `func NewControlClient(address string) (*ControlClient, error)`, `func (c *ControlClient) AddReConnectionCallback(cb ReConnectCB)`, and the pure helper `func shouldFireResync(old, new connectivity.State) bool` that later tasks do not call directly but that Task 9's design (connectivity-triggered resync) depends on being correct.

- [ ] **Step 1: Write the failing test for the pure transition-detection helper**

```go
package heavyagent

import (
	"testing"

	"google.golang.org/grpc/connectivity"
)

func TestShouldFireResync(t *testing.T) {
	tests := []struct {
		name string
		old  connectivity.State
		new  connectivity.State
		want bool
	}{
		{"transient failure to ready fires", connectivity.TransientFailure, connectivity.Ready, true},
		{"idle to ready does not fire", connectivity.Idle, connectivity.Ready, false},
		{"ready to transient failure does not fire", connectivity.Ready, connectivity.TransientFailure, false},
		{"connecting to ready does not fire", connectivity.Connecting, connectivity.Ready, false},
		{"transient failure to connecting does not fire", connectivity.TransientFailure, connectivity.Connecting, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldFireResync(tt.old, tt.new); got != tt.want {
				t.Errorf("shouldFireResync(%v, %v) = %v, want %v", tt.old, tt.new, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/daemon/pkg/heavy-agent/... -run TestShouldFireResync -v`
Expected: FAIL (build error: `shouldFireResync` undefined)

- [ ] **Step 3: Write `control_client.go`**

```go
package heavyagent

import (
	"context"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
	"gitlab.com/security-rd/go-pkg/logging"
)

// ControlClient wraps the generated NetPolicyControlClient with the
// connectivity-state-based resync-callback mechanism that replaces
// Client's TCP-reconnect-triggered ReConnectCB.
type ControlClient struct {
	pb.NetPolicyControlClient

	conn *grpc.ClientConn

	mu  sync.Mutex
	cbs []ReConnectCB
}

func NewControlClient(address string) (*ControlClient, error) {
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	c := &ControlClient{
		NetPolicyControlClient: pb.NewNetPolicyControlClient(conn),
		conn:                   conn,
	}
	go c.watchConnectivity()
	return c, nil
}

// AddReConnectionCallback registers cb to run whenever the underlying
// connection transitions from TRANSIENT_FAILURE back to READY -- the
// gRPC-native signal for "the peer was unreachable and is now back,"
// replacing the TCP client's reconnect-on-EOF trigger.
func (c *ControlClient) AddReConnectionCallback(cb ReConnectCB) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cbs = append(c.cbs, cb)
}

// shouldFireResync reports whether a connectivity transition from old to
// new should trigger the registered resync callbacks.
func shouldFireResync(old, new connectivity.State) bool {
	return old == connectivity.TransientFailure && new == connectivity.Ready
}

func (c *ControlClient) watchConnectivity() {
	state := c.conn.GetState()
	for {
		if !c.conn.WaitForStateChange(context.Background(), state) {
			return
		}
		newState := c.conn.GetState()
		if shouldFireResync(state, newState) {
			c.mu.Lock()
			cbs := append([]ReConnectCB(nil), c.cbs...)
			c.mu.Unlock()
			for _, cb := range cbs {
				if err := cb(); err != nil {
					logging.Get().Err(err).Msg("control-plane resync callback failed")
				}
			}
		}
		state = newState
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/daemon/pkg/heavy-agent/... -run TestShouldFireResync -v`
Expected: PASS

- [ ] **Step 5: Write the failing bufconn-based RPC test**

```go
package heavyagent

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
)

type fakeControlServer struct {
	pb.UnimplementedNetPolicyControlServer
	lastAddReq *pb.AddPolicyRuleRequest
}

func (f *fakeControlServer) AddPolicyRule(_ context.Context, req *pb.AddPolicyRuleRequest) (*pb.StatusResponse, error) {
	f.lastAddReq = req
	return &pb.StatusResponse{Status: 0}, nil
}

func newBufconnControlClient(t *testing.T, srv *fakeControlServer) *ControlClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	pb.RegisterNetPolicyControlServer(s, srv)
	go func() {
		_ = s.Serve(lis)
	}()
	t.Cleanup(s.Stop)

	conn, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return &ControlClient{
		NetPolicyControlClient: pb.NewNetPolicyControlClient(conn),
		conn:                   conn,
	}
}

func TestControlClient_AddPolicyRule(t *testing.T) {
	srv := &fakeControlServer{}
	client := newBufconnControlClient(t, srv)

	resp, err := client.AddPolicyRule(context.Background(), &pb.AddPolicyRuleRequest{PolicyName: "test-policy"})
	if err != nil {
		t.Fatalf("AddPolicyRule: %v", err)
	}
	if resp.GetStatus() != 0 {
		t.Errorf("status = %d, want 0", resp.GetStatus())
	}
	if srv.lastAddReq.GetPolicyName() != "test-policy" {
		t.Errorf("server received policy_name = %q, want %q", srv.lastAddReq.GetPolicyName(), "test-policy")
	}
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./cmd/daemon/pkg/heavy-agent/... -run TestControlClient_AddPolicyRule -v`
Expected: FAIL if Step 3 wasn't already done (it was) — actually expected to PASS immediately since `ControlClient`/`pb` already exist from prior steps. If it fails, the error must be a real bug in Step 3's code, not a missing symbol.

- [ ] **Step 7: Run full package tests to confirm everything passes together**

Run: `go test ./cmd/daemon/pkg/heavy-agent/... -v`
Expected: PASS (both new tests, plus any pre-existing tests in the package)

- [ ] **Step 8: Commit**

```bash
git add cmd/daemon/pkg/heavy-agent/control_client.go cmd/daemon/pkg/heavy-agent/control_client_test.go
git commit -m "feat(daemon): add gRPC ControlClient to pkg/heavy-agent"
```

---

### Task 3: `EventsClient` in pkg/heavy-agent

**Files:**
- Create: `cmd/daemon/pkg/heavy-agent/events_client.go`
- Test: `cmd/daemon/pkg/heavy-agent/events_client_test.go`

**Interfaces:**
- Consumes: `pb.NetPolicyEventsClient`, `pb.NewNetPolicyEventsClient`, `pb.PolicyMatchEvent`, `pb.PolicyEvent.GetPolicyMatch() *pb.PolicyMatchEvent` (Task 1).
- Produces: `type EventsClient struct { ... }`, `func NewEventsClient(address string) (*EventsClient, error)`, `func (c *EventsClient) Run(ctx context.Context, onEvent func(*pb.PolicyMatchEvent))` — loops `SubscribeEvents`, dispatches each `PolicyMatchEvent` to `onEvent`, and on any stream error backs off and retries. Returns when `ctx` is cancelled. Consumed by Task 9 (`main.go`).

- [ ] **Step 1: Write the failing test**

```go
package heavyagent

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
)

type fakeEventsServer struct {
	pb.UnimplementedNetPolicyEventsServer
	events []*pb.PolicyMatchEvent
	// failFirst, if true, makes the very first SubscribeEvents call return
	// an error with no events, to exercise EventsClient.Run's retry path.
	failFirst bool
	attempt   int
}

func (f *fakeEventsServer) SubscribeEvents(_ *pb.SubscribeEventsRequest, stream pb.NetPolicyEvents_SubscribeEventsServer) error {
	f.attempt++
	if f.failFirst && f.attempt == 1 {
		return context.DeadlineExceeded
	}
	for _, evt := range f.events {
		if err := stream.Send(&pb.PolicyEvent{Event: &pb.PolicyEvent_PolicyMatch{PolicyMatch: evt}}); err != nil {
			return err
		}
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func newBufconnEventsClient(t *testing.T, srv *fakeEventsServer) *EventsClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	pb.RegisterNetPolicyEventsServer(s, srv)
	go func() {
		_ = s.Serve(lis)
	}()
	t.Cleanup(s.Stop)

	conn, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return &EventsClient{client: pb.NewNetPolicyEventsClient(conn)}
}

func TestEventsClient_Run_DispatchesEvents(t *testing.T) {
	want := &pb.PolicyMatchEvent{PolicyName: "test-policy", SrcIp: "10.0.0.1"}
	srv := &fakeEventsServer{events: []*pb.PolicyMatchEvent{want}}
	client := newBufconnEventsClient(t, srv)

	received := make(chan *pb.PolicyMatchEvent, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go client.Run(ctx, func(evt *pb.PolicyMatchEvent) { received <- evt })

	select {
	case got := <-received:
		if got.GetPolicyName() != want.GetPolicyName() {
			t.Errorf("policy_name = %q, want %q", got.GetPolicyName(), want.GetPolicyName())
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestEventsClient_Run_RetriesOnStreamError(t *testing.T) {
	want := &pb.PolicyMatchEvent{PolicyName: "after-retry"}
	srv := &fakeEventsServer{events: []*pb.PolicyMatchEvent{want}, failFirst: true}
	client := newBufconnEventsClient(t, srv)

	received := make(chan *pb.PolicyMatchEvent, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go client.Run(ctx, func(evt *pb.PolicyMatchEvent) { received <- evt })

	select {
	case got := <-received:
		if got.GetPolicyName() != want.GetPolicyName() {
			t.Errorf("policy_name = %q, want %q", got.GetPolicyName(), want.GetPolicyName())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for event after retry")
	}
	if srv.attempt < 2 {
		t.Errorf("server saw %d SubscribeEvents attempts, want >= 2", srv.attempt)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/daemon/pkg/heavy-agent/... -run TestEventsClient -v`
Expected: FAIL (build error: `EventsClient` undefined)

- [ ] **Step 3: Write `events_client.go`**

```go
package heavyagent

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
	"gitlab.com/security-rd/go-pkg/logging"
)

const eventsRetryBackoff = 500 * time.Millisecond

// EventsClient streams PolicyMatchEvents from NetPolicyEvents, replacing
// the length-prefixed framing/dispatch loop in event.go's EventProcessor.
type EventsClient struct {
	client pb.NetPolicyEventsClient
	conn   *grpc.ClientConn
}

func NewEventsClient(address string) (*EventsClient, error) {
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &EventsClient{
		client: pb.NewNetPolicyEventsClient(conn),
		conn:   conn,
	}, nil
}

// Run subscribes to policy-match events and calls onEvent for each one
// received, re-subscribing with a short backoff whenever the stream ends
// (including on error). It returns when ctx is cancelled.
func (c *EventsClient) Run(ctx context.Context, onEvent func(*pb.PolicyMatchEvent)) {
	for {
		if ctx.Err() != nil {
			return
		}
		stream, err := c.client.SubscribeEvents(ctx, &pb.SubscribeEventsRequest{ClientId: "daemon"})
		if err != nil {
			logging.Get().Err(err).Msg("subscribe to policy events")
			time.Sleep(eventsRetryBackoff)
			continue
		}
		for {
			evt, err := stream.Recv()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logging.Get().Err(err).Msg("receive policy event")
				time.Sleep(eventsRetryBackoff)
				break
			}
			if match := evt.GetPolicyMatch(); match != nil {
				onEvent(match)
			}
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/daemon/pkg/heavy-agent/... -run TestEventsClient -v`
Expected: PASS (both `TestEventsClient_Run_DispatchesEvents` and `TestEventsClient_Run_RetriesOnStreamError`)

- [ ] **Step 5: Commit**

```bash
git add cmd/daemon/pkg/heavy-agent/events_client.go cmd/daemon/pkg/heavy-agent/events_client_test.go
git commit -m "feat(daemon): add gRPC EventsClient to pkg/heavy-agent"
```

---

### Task 4: Proto request-mapping helpers in pkg/microseg

**Files:**
- Create: `cmd/daemon/pkg/microseg/proto_mapping.go`
- Test: `cmd/daemon/pkg/microseg/proto_mapping_test.go`

**Interfaces:**
- Consumes: `pb.PolicyAction`/`FlowDirection`/`L4Protocol`/`PortRange`/`HttpMatchRule`/`AddressEndpoint`/`PolicyRuleSpec` (Task 1); `crdv1alpha1.NetworkPolicyPort`, `crdv1alpha1.Http` (`scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1`, already a repo dependency); the existing `Address`/`NodeRule` types in `pkg/microseg/policy_client.go` (unchanged by this task).
- Produces: `toPolicyAction(string) pb.PolicyAction`, `toFlowDirection(string) pb.FlowDirection`, `toL4Protocol(string) pb.L4Protocol`, `toPortRanges([]crdv1alpha1.NetworkPolicyPort) []*pb.PortRange`, `toHttpMatchRules([]*crdv1alpha1.Http) []*pb.HttpMatchRule`, `toAddressEndpoints([]Address) []*pb.AddressEndpoint`, `toPolicyRuleSpecs([]NodeRule) []*pb.PolicyRuleSpec` — all consumed by Task 5.

- [ ] **Step 1: Write the failing tests**

```go
package microseg

import (
	"testing"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestToPolicyAction(t *testing.T) {
	tests := []struct {
		in   string
		want pb.PolicyAction
	}{
		{"Allow", pb.PolicyAction_POLICY_ACTION_ALLOW},
		{"Log", pb.PolicyAction_POLICY_ACTION_ALLOW},
		{"Alert", pb.PolicyAction_POLICY_ACTION_ALERT},
		{"Deny", pb.PolicyAction_POLICY_ACTION_DENY},
		{"", pb.PolicyAction_POLICY_ACTION_DENY},
	}
	for _, tt := range tests {
		if got := toPolicyAction(tt.in); got != tt.want {
			t.Errorf("toPolicyAction(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestToFlowDirection(t *testing.T) {
	tests := []struct {
		in   string
		want pb.FlowDirection
	}{
		{"ingress", pb.FlowDirection_FLOW_DIRECTION_INGRESS},
		{"egress", pb.FlowDirection_FLOW_DIRECTION_EGRESS},
		{"", pb.FlowDirection_FLOW_DIRECTION_EGRESS},
	}
	for _, tt := range tests {
		if got := toFlowDirection(tt.in); got != tt.want {
			t.Errorf("toFlowDirection(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestToL4Protocol(t *testing.T) {
	tests := []struct {
		in   string
		want pb.L4Protocol
	}{
		{"TCP", pb.L4Protocol_L4_PROTOCOL_TCP},
		{"UDP", pb.L4Protocol_L4_PROTOCOL_UDP},
		{"ICMP", pb.L4Protocol_L4_PROTOCOL_ICMP},
		{"", pb.L4Protocol_L4_PROTOCOL_UNSPECIFIED},
		{"SCTP", pb.L4Protocol_L4_PROTOCOL_UNSPECIFIED},
	}
	for _, tt := range tests {
		if got := toL4Protocol(tt.in); got != tt.want {
			t.Errorf("toL4Protocol(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestToPortRanges(t *testing.T) {
	port := intstr.FromInt(8080)
	endPort := int32(8090)
	in := []crdv1alpha1.NetworkPolicyPort{{Port: &port, EndPort: &endPort}}

	got := toPortRanges(in)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].GetPort() != 8080 || got[0].GetEndPort() != 8090 {
		t.Errorf("got %+v, want port=8080 end_port=8090", got[0])
	}
}

func TestToAddressEndpoints(t *testing.T) {
	in := []Address{{IP: "10.0.0.1", PodID: 42}}
	got := toAddressEndpoints(in)
	if len(got) != 1 || got[0].GetIp() != "10.0.0.1" || got[0].GetPodId() != 42 {
		t.Errorf("got %+v, want ip=10.0.0.1 pod_id=42", got)
	}
}

func TestToPolicyRuleSpecs(t *testing.T) {
	in := []NodeRule{{
		Action:      "Allow",
		Direction:   "ingress",
		Protocol:    "TCP",
		Priority:    10,
		FromAddress: []Address{{IP: "10.0.0.1", PodID: 1}},
		ToAddresses: []Address{{IP: "10.0.0.2", PodID: 2}},
		Http:        []*crdv1alpha1.Http{{Host: "example.com", Method: "GET", Path: "/"}},
	}}
	got := toPolicyRuleSpecs(in)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	spec := got[0]
	if spec.GetAction() != pb.PolicyAction_POLICY_ACTION_ALLOW {
		t.Errorf("action = %v, want ALLOW", spec.GetAction())
	}
	if spec.GetDirection() != pb.FlowDirection_FLOW_DIRECTION_INGRESS {
		t.Errorf("direction = %v, want INGRESS", spec.GetDirection())
	}
	if spec.GetPriority() != 10 {
		t.Errorf("priority = %d, want 10", spec.GetPriority())
	}
	if len(spec.GetHttpRules()) != 1 || spec.GetHttpRules()[0].GetHost() != "example.com" {
		t.Errorf("http_rules = %+v, want one rule with host=example.com", spec.GetHttpRules())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/daemon/pkg/microseg/... -run 'TestToPolicyAction|TestToFlowDirection|TestToL4Protocol|TestToPortRanges|TestToAddressEndpoints|TestToPolicyRuleSpecs' -v`
Expected: FAIL (build error: `toPolicyAction` etc. undefined)

- [ ] **Step 3: Write `proto_mapping.go`**

```go
package microseg

import (
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

// toPolicyAction mirrors ConvertRuleAction, net-policy.cpp:1397-1403:
// "Allow"/"Log" -> allow, "Alert" -> alert, anything else -> deny.
func toPolicyAction(action string) pb.PolicyAction {
	switch action {
	case "Allow", "Log":
		return pb.PolicyAction_POLICY_ACTION_ALLOW
	case "Alert":
		return pb.PolicyAction_POLICY_ACTION_ALERT
	default:
		return pb.PolicyAction_POLICY_ACTION_DENY
	}
}

// toFlowDirection mirrors ParseNetPolicy's direction parsing, net-policy.cpp:1498-1500:
// exact-match "ingress" (lowercase), anything else is egress.
func toFlowDirection(direction string) pb.FlowDirection {
	if direction == "ingress" {
		return pb.FlowDirection_FLOW_DIRECTION_INGRESS
	}
	return pb.FlowDirection_FLOW_DIRECTION_EGRESS
}

// toL4Protocol mirrors NetProtoConvert, net-policy.cpp:60-71.
func toL4Protocol(protocol string) pb.L4Protocol {
	switch protocol {
	case "TCP":
		return pb.L4Protocol_L4_PROTOCOL_TCP
	case "UDP":
		return pb.L4Protocol_L4_PROTOCOL_UDP
	case "ICMP":
		return pb.L4Protocol_L4_PROTOCOL_ICMP
	default:
		return pb.L4Protocol_L4_PROTOCOL_UNSPECIFIED
	}
}

func toPortRanges(ports []crdv1alpha1.NetworkPolicyPort) []*pb.PortRange {
	if len(ports) == 0 {
		return nil
	}
	out := make([]*pb.PortRange, 0, len(ports))
	for _, p := range ports {
		var port, endPort uint32
		if p.Port != nil {
			port = uint32(p.Port.IntValue())
		}
		if p.EndPort != nil {
			endPort = uint32(*p.EndPort)
		}
		out = append(out, &pb.PortRange{Port: port, EndPort: endPort})
	}
	return out
}

func toHttpMatchRules(rules []*crdv1alpha1.Http) []*pb.HttpMatchRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]*pb.HttpMatchRule, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		out = append(out, &pb.HttpMatchRule{Host: r.Host, Method: r.Method, Path: r.Path})
	}
	return out
}

func toAddressEndpoints(addrs []Address) []*pb.AddressEndpoint {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]*pb.AddressEndpoint, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, &pb.AddressEndpoint{Ip: a.IP, PodId: a.PodID})
	}
	return out
}

func toPolicyRuleSpecs(rules []NodeRule) []*pb.PolicyRuleSpec {
	if len(rules) == 0 {
		return nil
	}
	out := make([]*pb.PolicyRuleSpec, 0, len(rules))
	for _, r := range rules {
		out = append(out, &pb.PolicyRuleSpec{
			Action:        toPolicyAction(r.Action),
			Direction:     toFlowDirection(r.Direction),
			Protocol:      toL4Protocol(r.Protocol),
			HttpRules:     toHttpMatchRules(r.Http),
			FromAddresses: toAddressEndpoints(r.FromAddress),
			ToAddresses:   toAddressEndpoints(r.ToAddresses),
			Ports:         toPortRanges(r.Ports),
			Priority:      int32(r.Priority),
		})
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/daemon/pkg/microseg/... -run 'TestToPolicyAction|TestToFlowDirection|TestToL4Protocol|TestToPortRanges|TestToAddressEndpoints|TestToPolicyRuleSpecs' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/daemon/pkg/microseg/proto_mapping.go cmd/daemon/pkg/microseg/proto_mapping_test.go
git commit -m "feat(daemon): add CRD-to-proto mapping helpers for microseg policy rules"
```

---

### Task 5: Rewrite `pkg/microseg.PolicyClient` against `ControlClient`

**Files:**
- Modify: `cmd/daemon/pkg/microseg/policy_client.go` (the `PolicyClient` interface, `policyClient` struct, `NewPolicyClient`, `AddPolicy`, `DeletePolicy`, `AddContainer`, `DeleteContaier`; keeps `Address`/`NodeRule`/`PolicyRule`/`ContainerInfo`/`MetaData` types as-is)
- Modify: `cmd/daemon/pkg/microseg/policy_client_test.go` (full rewrite)

**Interfaces:**
- Consumes: `*heavyagent.ControlClient` (Task 2), `toPolicyRuleSpecs` (Task 4), `pb.AddPolicyRuleRequest`/`DeletePolicyRuleRequest`/`PodUpRequest`/`PodDownRequest` (Task 1).
- Produces: `PolicyClient` interface unchanged in method set consumed elsewhere (`AddPolicy(*PolicyRule) error`, `DeletePolicy(*PolicyRule) error`, `AddContainer(pid int, podID uint64) error`, `DeleteContaier(pid int, podID uint64) error`, `AddReConnectionCallback(heavyagent.ReConnectCB)`); `NewPolicyClient(*heavyagent.ControlClient) PolicyClient` — the type of its parameter is the only breaking signature change, consumed by Task 9. `GetConn()`/`ReConnect()`/`Stop()` are dropped from the interface (confirmed unused by any caller outside this package).

- [ ] **Step 1: Replace `policy_client.go`'s client/interface section**

Replace lines 1–75 of `cmd/daemon/pkg/microseg/policy_client.go` (imports through `NewPolicyClient`) with:

```go
package microseg

import (
	"context"
	"fmt"
	"time"

	heavyagent "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

const requestTimeout = 3 * time.Second

type Address struct {
	IP    string `json:"ip"`
	PodID uint64 `json:"pod_id,omitempty"`
}

type NodeRule struct {
	Priority    int
	Protocol    string
	Direction   string
	Action      string
	Ports       []crdv1alpha1.NetworkPolicyPort `json:"ports,omitempty"`
	ToAddresses []Address                       `json:"to_addresses,omitempty"`
	FromAddress []Address                       `json:"from_addresses,omitempty"`
	Http        []*crdv1alpha1.Http             `json:"http,omitempty"`
}

type MetaData struct {
	UUID string `json:"uuid"`
}
type PolicyRule struct {
	MetaData
	MessageType int        `json:"msg_type"`
	PolicyName  string     `json:"policy_name"`
	Rules       []NodeRule `json:"rules,omitempty"`
}

type ContainerInfo struct {
	MetaData
	MessageType int    `json:"msg_type"`
	Pid         int    `json:"pid"`
	PodID       uint64 `json:"pod_id"`
}

type PolicyClient interface {
	AddPolicy(rule *PolicyRule) error
	DeletePolicy(rule *PolicyRule) error

	AddContainer(pid int, podID uint64) error
	DeleteContaier(pid int, podID uint64) error

	AddReConnectionCallback(cb heavyagent.ReConnectCB)
}

type policyClient struct {
	*heavyagent.ControlClient
}

var _ PolicyClient = (*policyClient)(nil)

func NewPolicyClient(cli *heavyagent.ControlClient) PolicyClient {
	return &policyClient{
		ControlClient: cli,
	}
}
```

- [ ] **Step 2: Replace `AddPolicy`/`DeletePolicy`/`AddContainer`/`DeleteContaier` and delete the now-unused `sendMessage`/`receiveResponse` helpers and `Response` type**

Replace everything from the old `func (cli *policyClient) AddPolicy` through the old `func (cli *policyClient) AddReConnectionCallback` (the rest of the file) with:

```go
func (cli *policyClient) AddPolicy(rule *PolicyRule) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := cli.AddPolicyRule(ctx, &pb.AddPolicyRuleRequest{
		PolicyName: rule.PolicyName,
		Rules:      toPolicyRuleSpecs(rule.Rules),
	})
	if err != nil {
		return err
	}
	if resp.GetStatus() != 0 {
		return fmt.Errorf("data plane err :%d", resp.GetStatus())
	}
	return nil
}

func (cli *policyClient) DeletePolicy(rule *PolicyRule) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := cli.DeletePolicyRule(ctx, &pb.DeletePolicyRuleRequest{PolicyName: rule.PolicyName})
	if err != nil {
		return err
	}
	if resp.GetStatus() != 0 {
		return fmt.Errorf("data plane err :%d", resp.GetStatus())
	}
	return nil
}

func (cli *policyClient) AddContainer(pid int, podID uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := cli.PodUp(ctx, &pb.PodUpRequest{Pid: int32(pid), PodId: podID})
	if err != nil {
		return err
	}
	if resp.GetStatus() != 0 {
		return fmt.Errorf("data plane err :%d", resp.GetStatus())
	}
	return nil
}

func (cli *policyClient) DeleteContaier(pid int, podID uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := cli.PodDown(ctx, &pb.PodDownRequest{PodId: podID})
	if err != nil {
		return err
	}
	if resp.GetStatus() != 0 {
		return fmt.Errorf("data plane err :%d", resp.GetStatus())
	}
	return nil
}
```

Note: `AddReConnectionCallback` needs no explicit definition anymore — it's promoted from the embedded `*heavyagent.ControlClient` (Task 2), satisfying the `PolicyClient` interface automatically.

- [ ] **Step 3: Rewrite `policy_client_test.go`**

```go
package microseg

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	heavyagent "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
)

type fakeControlServer struct {
	pb.UnimplementedNetPolicyControlServer
	lastDeleteReq *pb.DeletePolicyRuleRequest
	lastPodUpReq  *pb.PodUpRequest
	status        int32
}

func (f *fakeControlServer) DeletePolicyRule(_ context.Context, req *pb.DeletePolicyRuleRequest) (*pb.StatusResponse, error) {
	f.lastDeleteReq = req
	return &pb.StatusResponse{Status: f.status}, nil
}

func (f *fakeControlServer) PodUp(_ context.Context, req *pb.PodUpRequest) (*pb.StatusResponse, error) {
	f.lastPodUpReq = req
	return &pb.StatusResponse{Status: f.status}, nil
}

func newTestPolicyClient(t *testing.T, srv *fakeControlServer) PolicyClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	pb.RegisterNetPolicyControlServer(s, srv)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)

	conn, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return NewPolicyClient(&heavyagent.ControlClient{
		NetPolicyControlClient: pb.NewNetPolicyControlClient(conn),
	})
}

func Test_policyClient_DeletePolicy(t *testing.T) {
	srv := &fakeControlServer{}
	cli := newTestPolicyClient(t, srv)

	err := cli.DeletePolicy(&PolicyRule{PolicyName: "test-policy"})
	if err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	if srv.lastDeleteReq.GetPolicyName() != "test-policy" {
		t.Errorf("server received policy_name = %q, want %q", srv.lastDeleteReq.GetPolicyName(), "test-policy")
	}
}

func Test_policyClient_DeletePolicy_NonZeroStatus(t *testing.T) {
	srv := &fakeControlServer{status: 1}
	cli := newTestPolicyClient(t, srv)

	if err := cli.DeletePolicy(&PolicyRule{PolicyName: "test-policy"}); err == nil {
		t.Fatal("DeletePolicy: want error for non-zero status, got nil")
	}
}

func Test_policyClient_AddContainer(t *testing.T) {
	srv := &fakeControlServer{}
	cli := newTestPolicyClient(t, srv)

	if err := cli.AddContainer(123, 456); err != nil {
		t.Fatalf("AddContainer: %v", err)
	}
	if srv.lastPodUpReq.GetPid() != 123 || srv.lastPodUpReq.GetPodId() != 456 {
		t.Errorf("server received %+v, want pid=123 pod_id=456", srv.lastPodUpReq)
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go build ./cmd/daemon/... && go test ./cmd/daemon/pkg/microseg/... -run 'Test_policyClient' -v`
Expected: `go build` succeeds for every package that only depends on `PolicyClient`'s interface (note: `cmd/daemon/pkg/microseg/policyrule_controller.go` and `cmd/daemon/main.go` will NOT build yet — they still reference the old `*heavyagent.Client` constructor signatures and are fixed in Tasks 6 and 9; run `go build ./cmd/daemon/pkg/microseg/... ./cmd/daemon/pkg/heavy-agent/...` scoped to what's done so far if the full `./cmd/daemon/...` build fails for that reason). The three new tests PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/daemon/pkg/microseg/policy_client.go cmd/daemon/pkg/microseg/policy_client_test.go
git commit -m "feat(daemon): rewrite microseg.PolicyClient against gRPC ControlClient"
```

---

### Task 6: `RuleGroupController` → `ControlClient`, and `DumpConfig`-based `checkSync`

**Files:**
- Modify: `cmd/daemon/pkg/microseg/policyrule_controller.go` (struct field, constructor signature, `checkSync` body, import block)
- Modify: `cmd/daemon/pkg/microseg/types/microseg/types.go` (remove `ConfigDumpReq`, `ConfigDumpResp`, `RespBody`; keep `SingleRule`)

**Interfaces:**
- Consumes: `*heavyagent.ControlClient` (Task 2), `pb.DumpConfigRequest`/`DumpConfigResponse`/`PolicyRuleConfigEntry` (Task 1).
- Produces: `NewRuleGroupController(clientset *versioned.Clientset, crdFactory externalversions.SharedInformerFactory, cli PolicyClient, nodeName string, mqWriter mq.Writer, agentCli *heavyagent.ControlClient) *RuleGroupController` — the changed parameter type is consumed by Task 9.

- [ ] **Step 1: Change the struct field and constructor signature**

In `cmd/daemon/pkg/microseg/policyrule_controller.go`, change:

```go
	agentCli        *heavyagent.Client
```
to:
```go
	agentCli        *heavyagent.ControlClient
```

and change:
```go
func NewRuleGroupController(clientset *versioned.Clientset, crdFactory externalversions.SharedInformerFactory, cli PolicyClient, nodeName string, mqWriter mq.Writer, agentCli *heavyagent.Client) *RuleGroupController {
```
to:
```go
func NewRuleGroupController(clientset *versioned.Clientset, crdFactory externalversions.SharedInformerFactory, cli PolicyClient, nodeName string, mqWriter mq.Writer, agentCli *heavyagent.ControlClient) *RuleGroupController {
```

- [ ] **Step 2: Rewrite `checkSync`'s agent-dump section**

Replace this block inside `checkSync` (currently reading: build `microseg.ConfigDumpReq`, `json.Marshal`, `rg.agentCli.SendAndReceiveMessage(data, &resp)`):

```go
	req := microseg.ConfigDumpReq{
		UUID:        uuid.NewString(),
		MessageType: 10,
	}
	data, err := json.Marshal(&req)
	if err != nil {
		return err
	}
	// err = rg.agentCli.Send(data)
	// if err != nil {
	// 	return err
	// }

	// var resp microseg.ConfigDumpResp
	// err = rg.agentCli.ReceiveMessage(&resp)
	// if err != nil {
	// 	return err
	// }

	var resp microseg.ConfigDumpResp
	err = rg.agentCli.SendAndReceiveMessage(data, &resp)
	if err != nil {
		return err
	}

	logging.Get().Info().Msgf("agent config inbound: %d, outbound %d", len(resp.Body.InboundRules), len(resp.Body.OutboundRules))
```

with:

```go
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := rg.agentCli.DumpConfig(ctx, &pb.DumpConfigRequest{})
	if err != nil {
		return err
	}

	logging.Get().Info().Msgf("agent config inbound: %d, outbound %d", len(resp.GetInboundRules()), len(resp.GetOutboundRules()))
```

Then, further down in the same function, replace the two range loops (`for _, r := range resp.Body.InboundRules` and `for _, r := range resp.Body.OutboundRules`) so they range over `resp.GetInboundRules()`/`resp.GetOutboundRules()` (each element now `*pb.PolicyRuleConfigEntry` instead of `microseg.SingleRule`) — change every `r.Protocol`/`r.PolicyName`/`r.Priority`/`r.Direction`/`r.Action`/`r.FromAddress`/`r.ToAddress` field access in those two loops to the generated getters `r.GetProtocol()`/`r.GetPolicyName()`/`r.GetPriority()`/`r.GetDirection()`/`r.GetAction()`/`r.GetFromAddress()`/`r.GetToAddress()`, and change `Priority: r.Priority` (an `int32` from the proto) to `Priority: int(r.GetPriority())` when constructing each `microseg.SingleRule{...}` — every other field assignment in those two loops keeps the exact same shape, just reading through the proto getters.

- [ ] **Step 3: Fix imports**

In `cmd/daemon/pkg/microseg/policyrule_controller.go`'s import block: remove `"github.com/google/uuid"` (no longer used anywhere in this file after Step 2 — confirm with `grep -n uuid\\. cmd/daemon/pkg/microseg/policyrule_controller.go` returning nothing before removing), add `"context"`, `"time"`, and `"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"`.

- [ ] **Step 4: Trim `types/microseg/types.go`**

In `cmd/daemon/pkg/microseg/types/microseg/types.go`, delete the `ConfigDumpReq`, `RespBody`, and `ConfigDumpResp` type declarations, keeping only `SingleRule`:

```go
package microseg

type SingleRule struct {
	PolicyName  string `json:"policy_name"`
	Priority    int    `json:"priority"`
	Direction   string `json:"direction"`
	Action      string `json:"action"`
	Protocol    string `json:"protocol"`
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
}
```

- [ ] **Step 5: Build**

Run: `go build ./cmd/daemon/pkg/microseg/...`
Expected: succeeds with no output.

- [ ] **Step 6: Run the package's existing tests**

Run: `go test ./cmd/daemon/pkg/microseg/... -v`
Expected: PASS (includes Task 4's and Task 5's tests, plus anything pre-existing in this package unaffected by these changes).

- [ ] **Step 7: Commit**

```bash
git add cmd/daemon/pkg/microseg/policyrule_controller.go cmd/daemon/pkg/microseg/types/microseg/types.go
git commit -m "feat(daemon): move RuleGroupController's config dump to gRPC DumpConfig"
```

---

### Task 7: Policy-match event payload mapping in pkg/microseg

**Files:**
- Create: `cmd/daemon/pkg/microseg/event_mapping.go`
- Test: `cmd/daemon/pkg/microseg/event_mapping_test.go`

**Interfaces:**
- Consumes: `pb.PolicyMatchEvent` (Task 1).
- Produces: `func EventPayloadFromPolicyMatch(evt *pb.PolicyMatchEvent) any` — consumed by Task 9's `main.go` wiring, passed straight into the existing `heavyagent.Handler.Handle(ctx, obj)` (`pkg/microseg/handle.go`, unchanged) which `json.Marshal`s it and POSTs to `cmd/clustermanager`'s `/internal/microseg/event`, decoded there into `gitlab.com/security-rd/go-pkg/model.TensorMicrosegEvent` (`Proto`/`Action`/`Direction` as `int`, matching `cmd/clustermanager/pkg/clusterserver/filter.go`'s `0/1/2`-Deny/Allow/Alert and `1/6/17`-ICMP/TCP/UDP switch statements exactly — see this plan's Global Constraints for the full mapping table).

- [ ] **Step 1: Write the failing test**

```go
package microseg

import (
	"encoding/json"
	"testing"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
)

func TestEventPayloadFromPolicyMatch(t *testing.T) {
	evt := &pb.PolicyMatchEvent{
		Protocol:   pb.L4Protocol_L4_PROTOCOL_TCP,
		Action:     pb.PolicyAction_POLICY_ACTION_ALLOW,
		Direction:  pb.FlowDirection_FLOW_DIRECTION_EGRESS,
		SrcPort:    12345,
		DstPort:    443,
		SrcIp:      "10.0.0.1",
		DstIp:      "10.0.0.2",
		PolicyName: "test-policy",
	}

	payload := EventPayloadFromPolicyMatch(evt)
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded struct {
		Proto      int    `json:"proto"`
		Action     int    `json:"action"`
		Direction  int    `json:"direction"`
		SrcPort    int    `json:"src_port"`
		DstPort    int    `json:"dst_port"`
		SrcIP      string `json:"src_ip"`
		DstIP      string `json:"dst_ip"`
		PolicyName string `json:"policy_name"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Proto != 6 {
		t.Errorf("proto = %d, want 6 (TCP)", decoded.Proto)
	}
	if decoded.Action != 1 {
		t.Errorf("action = %d, want 1 (Allow)", decoded.Action)
	}
	if decoded.Direction != 1 {
		t.Errorf("direction = %d, want 1 (Egress)", decoded.Direction)
	}
	if decoded.SrcPort != 12345 || decoded.DstPort != 443 {
		t.Errorf("ports = %d/%d, want 12345/443", decoded.SrcPort, decoded.DstPort)
	}
	if decoded.SrcIP != "10.0.0.1" || decoded.DstIP != "10.0.0.2" {
		t.Errorf("ips = %s/%s, want 10.0.0.1/10.0.0.2", decoded.SrcIP, decoded.DstIP)
	}
	if decoded.PolicyName != "test-policy" {
		t.Errorf("policy_name = %q, want test-policy", decoded.PolicyName)
	}
}

func TestPolicyActionToWireCode(t *testing.T) {
	tests := []struct {
		in   pb.PolicyAction
		want int
	}{
		{pb.PolicyAction_POLICY_ACTION_DENY, 0},
		{pb.PolicyAction_POLICY_ACTION_ALLOW, 1},
		{pb.PolicyAction_POLICY_ACTION_ALERT, 2},
		{pb.PolicyAction_POLICY_ACTION_UNSPECIFIED, 0},
	}
	for _, tt := range tests {
		if got := policyActionToWireCode(tt.in); got != tt.want {
			t.Errorf("policyActionToWireCode(%v) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestL4ProtocolToWireCode(t *testing.T) {
	tests := []struct {
		in   pb.L4Protocol
		want int
	}{
		{pb.L4Protocol_L4_PROTOCOL_TCP, 6},
		{pb.L4Protocol_L4_PROTOCOL_UDP, 17},
		{pb.L4Protocol_L4_PROTOCOL_ICMP, 1},
		{pb.L4Protocol_L4_PROTOCOL_UNSPECIFIED, 0},
	}
	for _, tt := range tests {
		if got := l4ProtocolToWireCode(tt.in); got != tt.want {
			t.Errorf("l4ProtocolToWireCode(%v) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/daemon/pkg/microseg/... -run 'TestEventPayloadFromPolicyMatch|TestPolicyActionToWireCode|TestL4ProtocolToWireCode' -v`
Expected: FAIL (build error: undefined symbols)

- [ ] **Step 3: Write `event_mapping.go`**

```go
package microseg

import "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"

// microsegEventPayload mirrors the fields gitlab.com/security-rd/go-pkg/model.TensorMicrosegEvent
// expects the daemon to populate (its embedded Base is filled in by clustermanager itself,
// see cmd/clustermanager/pkg/clusterserver/filter.go's FillResToMicroSegLog). The int codes
// for Proto/Action/Direction must match the legacy NET_POLICY_RULE/FLOW_DIR/IPPROTO_* values
// clustermanager's filter.go switches on -- NOT the new proto enums' own numbering.
type microsegEventPayload struct {
	Proto      int    `json:"proto"`
	Action     int    `json:"action"`
	Direction  int    `json:"direction"`
	SrcPort    int    `json:"src_port"`
	DstPort    int    `json:"dst_port"`
	SrcIP      string `json:"src_ip"`
	DstIP      string `json:"dst_ip"`
	PolicyName string `json:"policy_name"`
}

// policyActionToWireCode mirrors NET_POLICY_RULE (net-policy.h:74-82): Deny=0, Allow=1, Mark(Alert)=2.
func policyActionToWireCode(action pb.PolicyAction) int {
	switch action {
	case pb.PolicyAction_POLICY_ACTION_ALLOW:
		return 1
	case pb.PolicyAction_POLICY_ACTION_ALERT:
		return 2
	default:
		return 0
	}
}

// flowDirectionToWireCode mirrors FLOW_DIR (net-policy.h:85-89): Ingress=0, Egress=1.
func flowDirectionToWireCode(direction pb.FlowDirection) int {
	if direction == pb.FlowDirection_FLOW_DIRECTION_EGRESS {
		return 1
	}
	return 0
}

// l4ProtocolToWireCode mirrors the raw IPPROTO_* values NetProtoConvert produces
// (net-policy.cpp:60-71): ICMP=1, TCP=6, UDP=17.
func l4ProtocolToWireCode(protocol pb.L4Protocol) int {
	switch protocol {
	case pb.L4Protocol_L4_PROTOCOL_TCP:
		return 6
	case pb.L4Protocol_L4_PROTOCOL_UDP:
		return 17
	case pb.L4Protocol_L4_PROTOCOL_ICMP:
		return 1
	default:
		return 0
	}
}

// EventPayloadFromPolicyMatch converts a NetPolicyEvents PolicyMatchEvent into the
// JSON shape MicrosegHandler.Handle posts to clustermanager's /internal/microseg/event.
func EventPayloadFromPolicyMatch(evt *pb.PolicyMatchEvent) any {
	return microsegEventPayload{
		Proto:      l4ProtocolToWireCode(evt.GetProtocol()),
		Action:     policyActionToWireCode(evt.GetAction()),
		Direction:  flowDirectionToWireCode(evt.GetDirection()),
		SrcPort:    int(evt.GetSrcPort()),
		DstPort:    int(evt.GetDstPort()),
		SrcIP:      evt.GetSrcIp(),
		DstIP:      evt.GetDstIp(),
		PolicyName: evt.GetPolicyName(),
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/daemon/pkg/microseg/... -run 'TestEventPayloadFromPolicyMatch|TestPolicyActionToWireCode|TestL4ProtocolToWireCode' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/daemon/pkg/microseg/event_mapping.go cmd/daemon/pkg/microseg/event_mapping_test.go
git commit -m "feat(daemon): map PolicyMatchEvent to clustermanager's microseg event wire format"
```

---

### Task 8: Rewrite `status/server.go` against `ControlClient`

**Files:**
- Modify: `cmd/daemon/status/server.go`
- Create: `cmd/daemon/status/server_test.go`

**Interfaces:**
- Consumes: `*heavyagent.ControlClient` (Task 2), `pb.DumpConfigRequest`, `pb.SetLogLevelRequest`, `pb.DumpHeapProfileRequest`, `pb.DumpConnectionsRequest`, `pb.ResetConfigRequest`, `pb.StatusResponse` (Task 1).
- Produces: `NewServer(port uint16, cli *heavyagent.ControlClient) *Server` — the changed parameter type is consumed by Task 9.

- [ ] **Step 1: Replace the top of `server.go` (imports, request/response types, `NewServer`)**

Replace from the top of the file through `func NewServer(...)` with:

```go
package status

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	param "github.com/oceanicdev/chi-param"
	heavyagent "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
	"gitlab.com/security-rd/go-pkg/logging"
)

var log = logging.Get().With().Str("module", "status").Logger()

const requestTimeout = 3 * time.Second

type Server struct {
	port uint16
	cli  *heavyagent.ControlClient
}

func NewServer(port uint16, cli *heavyagent.ControlClient) *Server {
	return &Server{
		port: port,
		cli:  cli,
	}
}
```

(This drops the now-unused `AgentConfig`, `HeapDumpReq`, `ConfigDumpReq`, `LogLevelConfig`, `ConnDumpReq`, `Reset`, and `Response` types and the `github.com/google/uuid` import — every request/response shape is now the generated `pb` type.)

- [ ] **Step 2: Keep `Run` and the five `handle*` HTTP handlers unchanged**, and replace the five request-building methods

Replace `dumpAgentConfig`, `SetAgentLogLevelReq`, `dumpAgentHeap`, `dumpAgentConn`, `reset` with:

```go
func (s *Server) dumpAgentConfig(name string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := s.cli.DumpConfig(ctx, &pb.DumpConfigRequest{PolicyName: name})
	if err != nil {
		return nil, err
	}
	return json.Marshal(resp)
}

func (s *Server) SetAgentLogLevelReq(level int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := s.cli.SetLogLevel(ctx, &pb.SetLogLevelRequest{Level: int32(level)})
	if err != nil {
		return nil, err
	}
	return json.Marshal(resp)
}

func (s *Server) dumpAgentHeap(enable string) (*pb.StatusResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := s.cli.DumpHeapProfile(ctx, &pb.DumpHeapProfileRequest{Enable: enable == "y"})
	if err != nil {
		return nil, err
	}
	if resp.GetStatus() != 0 {
		return nil, fmt.Errorf("agent err %d", resp.GetStatus())
	}
	return resp, nil
}

func (s *Server) dumpAgentConn(limit int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := s.cli.DumpConnections(ctx, &pb.DumpConnectionsRequest{Limit: int32(limit)})
	if err != nil {
		return nil, err
	}
	return json.Marshal(resp)
}

func (s *Server) reset() error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := s.cli.ResetConfig(ctx, &pb.ResetConfigRequest{})
	if err != nil {
		return err
	}
	if resp.GetStatus() != 0 {
		return fmt.Errorf("agent err %d", resp.GetStatus())
	}
	return nil
}
```

`handleDumpAgentConn`'s body currently does `resp, err := s.dumpAgentConn(limit)` then `var resp = &Response{}; json.Unmarshal(...)` for logging purposes only, discarding the result — leave `handleDumpAgentConn`, `handleDumpAgentConfig`, `SetAgentLogLevel`, `handleDumpAgentHeap`, `handleReset` exactly as they are; they already only call the methods above and write bytes/status codes, with no direct dependency on the old request/response type names.

- [ ] **Step 3: Write `server_test.go`**

```go
package status

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	heavyagent "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
)

type fakeControlServer struct {
	pb.UnimplementedNetPolicyControlServer
	lastResetCalled bool
}

func (f *fakeControlServer) ResetConfig(context.Context, *pb.ResetConfigRequest) (*pb.StatusResponse, error) {
	f.lastResetCalled = true
	return &pb.StatusResponse{Status: 0}, nil
}

func (f *fakeControlServer) DumpConfig(_ context.Context, req *pb.DumpConfigRequest) (*pb.DumpConfigResponse, error) {
	return &pb.DumpConfigResponse{
		InboundRules: []*pb.PolicyRuleConfigEntry{{PolicyName: req.GetPolicyName()}},
	}, nil
}

func newTestServer(t *testing.T, srv *fakeControlServer) *Server {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	pb.RegisterNetPolicyControlServer(s, srv)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)

	conn, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return NewServer(0, &heavyagent.ControlClient{NetPolicyControlClient: pb.NewNetPolicyControlClient(conn)})
}

func TestServer_reset(t *testing.T) {
	srv := &fakeControlServer{}
	s := newTestServer(t, srv)

	if err := s.reset(); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if !srv.lastResetCalled {
		t.Error("ResetConfig was not called on the server")
	}
}

func TestServer_dumpAgentConfig(t *testing.T) {
	srv := &fakeControlServer{}
	s := newTestServer(t, srv)

	data, err := s.dumpAgentConfig("test-policy")
	if err != nil {
		t.Fatalf("dumpAgentConfig: %v", err)
	}
	if len(data) == 0 {
		t.Error("dumpAgentConfig returned empty response")
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go build ./cmd/daemon/status/... && go test ./cmd/daemon/status/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/daemon/status/server.go cmd/daemon/status/server_test.go
git commit -m "feat(daemon): rewrite status/server.go debug endpoints against gRPC ControlClient"
```

---

### Task 9: Rewire `main.go` and delete the old `EventProcessor`

**Files:**
- Modify: `cmd/daemon/main.go` (the `MICROSEG_ENABLED` block inside `Run`)
- Modify: `cmd/daemon/pkg/heavy-agent/event.go` (delete `EventProcessor` and everything only it used)

**Interfaces:**
- Consumes: `heavyagent.NewControlClient`/`NewEventsClient` (Tasks 2–3), `microseg.NewPolicyClient`/`NewRuleGroupController`/`EventPayloadFromPolicyMatch` (Tasks 5–7), `status.NewServer` (Task 8), `pb.PolicyMatchEvent` (Task 1). `waf.NewWafClient`/`NewWafController` and `heavyagent.NewClient`/`Client` (unchanged, `pkg/waf` and the rest of `pkg/heavy-agent` are untouched).
- Produces: nothing consumed by later tasks — this is the final integration point.

- [ ] **Step 1: Replace the `MICROSEG_ENABLED` block**

In `cmd/daemon/main.go`'s `Run` function, replace the entire

```go
	if os.Getenv("MICROSEG_ENABLED") == "true" {

		var agentClient, agentEventClient *heavyagent.Client

		agentClient, err = heavyagent.NewClient("127.0.0.1:9999")
		if err != nil {
			return err
		}

		agentEventClient, err = heavyagent.NewClient("127.0.0.1:8888")
		if err != nil {
			return err
		}

		policyClient := microseg.NewPolicyClient(agentClient)
		if agentClient == nil {
			logging.Get().Error().Msg("agentClient is nil")
		}

		stopChan := make(chan struct{})

		controller := nodeinfo.NewPodController(podWatcher.PodLister(), podWatcher.PodInformer(), containerInfo, policyClient)
		go controller.Run(stopChan)

		tensorFactory := externalversions.NewSharedInformerFactoryWithOptions(clientset.TensorClientset, 10*time.Hour,
			externalversions.WithTweakListOptions(func(lo *v1.ListOptions) {
				lo.LabelSelector = fmt.Sprintf("kubernetes.io/node-name=%s", hostName)
			}))
		ruleController := microseg.NewRuleGroupController(clientset.TensorClientset, tensorFactory, policyClient, hostName, mqWriter, agentClient)

		go ruleController.Run(stopChan)

		var wafEnabled = true
		wafEnv := os.Getenv("WAF")
		if wafEnv == "true" {
			wafEnabled = true
		}
		if wafEnabled {
			wafClient := waf.NewWafClient(agentClient)
			wafController := waf.NewWafController(clientset.TensorClientset, factory, tensorFactory, podWatcher, wafClient)
			go wafController.Run(stopCh)
		}

		tensorFactory.Start(stopChan)
		tensorFactory.WaitForCacheSync(stopChan)

		clusterManagerSvc := os.Getenv("CLUSTER_MANAGER_URL")
		eventProcessor := heavyagent.NewEventProcessor(clusterManagerSvc, agentEventClient)

		microsegHandler := microseg.NewHandler(clusterManagerSvc)
		eventProcessor.AddHandler("microseg", microsegHandler)

		wafhander := waf.NewHandler(clusterManagerSvc)
		eventProcessor.AddHandler("waf", wafhander)

		go eventProcessor.Run1()
		go func() {
			srv := status.NewServer(12000, agentClient)
			srv.Run()
		}()
	}
```

with:

```go
	if os.Getenv("MICROSEG_ENABLED") == "true" {
		ctrlClient, err := heavyagent.NewControlClient("127.0.0.1:50051")
		if err != nil {
			return err
		}

		eventsClient, err := heavyagent.NewEventsClient("127.0.0.1:50052")
		if err != nil {
			return err
		}

		policyClient := microseg.NewPolicyClient(ctrlClient)

		stopChan := make(chan struct{})

		controller := nodeinfo.NewPodController(podWatcher.PodLister(), podWatcher.PodInformer(), containerInfo, policyClient)
		go controller.Run(stopChan)

		tensorFactory := externalversions.NewSharedInformerFactoryWithOptions(clientset.TensorClientset, 10*time.Hour,
			externalversions.WithTweakListOptions(func(lo *v1.ListOptions) {
				lo.LabelSelector = fmt.Sprintf("kubernetes.io/node-name=%s", hostName)
			}))
		ruleController := microseg.NewRuleGroupController(clientset.TensorClientset, tensorFactory, policyClient, hostName, mqWriter, ctrlClient)

		go ruleController.Run(stopChan)

		// net-policy dropped WAF support entirely (no gRPC equivalent exists), so this
		// dials the now-dead port 9999. heavyagent.NewClient blocks retrying forever
		// until something accepts the connection, so this must run in its own
		// goroutine rather than on Run's main startup path.
		go func() {
			agentClient, err := heavyagent.NewClient("127.0.0.1:9999")
			if err != nil {
				logging.Get().Err(err).Msg("dial legacy waf agent client")
				return
			}
			wafClient := waf.NewWafClient(agentClient)
			wafController := waf.NewWafController(clientset.TensorClientset, factory, tensorFactory, podWatcher, wafClient)
			wafController.Run(stopCh)
		}()

		tensorFactory.Start(stopChan)
		tensorFactory.WaitForCacheSync(stopChan)

		clusterManagerSvc := os.Getenv("CLUSTER_MANAGER_URL")
		microsegHandler := microseg.NewHandler(clusterManagerSvc)

		go eventsClient.Run(ctx, func(evt *pb.PolicyMatchEvent) {
			if err := microsegHandler.Handle(ctx, microseg.EventPayloadFromPolicyMatch(evt)); err != nil {
				logging.Get().Err(err).Msg("post microseg event err")
			}
		})

		go func() {
			srv := status.NewServer(12000, ctrlClient)
			srv.Run()
		}()
	}
```

- [ ] **Step 2: Add the `pb` import**

In `cmd/daemon/main.go`'s import block, add:

```go
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
```

(alongside the existing `heavyagent "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent"` import, which stays since `heavyagent.NewClient`/`heavyagent.NewControlClient`/`heavyagent.NewEventsClient` are all still referenced.)

- [ ] **Step 3: Delete `EventProcessor` from `pkg/heavy-agent/event.go`**

`heavyagent.EventProcessor`/`NewEventProcessor`/`Run`/`Run1`/`readHeader`/`handlerError`/`AddHandler` and the `EventHeader`/`AttackLogDetail` types are referenced nowhere else in the repository (confirmed by repo-wide grep before writing this plan) once Step 1 lands. Delete `cmd/daemon/pkg/heavy-agent/event.go` in full. Leave `cmd/daemon/pkg/heavy-agent/handle.go` (the `Handler` interface) untouched — `pkg/waf/handle.go`'s `NewHandler` still returns `heavyagent.Handler`, and `pkg/microseg/handle.go`'s `NewHandler` does too.

```bash
rm cmd/daemon/pkg/heavy-agent/event.go
```

- [ ] **Step 4: Build the whole daemon**

Run: `go build ./cmd/daemon/...`
Expected: succeeds with no output.

- [ ] **Step 5: Run every touched package's tests together**

Run: `go test ./cmd/daemon/pkg/heavy-agent/... ./cmd/daemon/pkg/microseg/... ./cmd/daemon/status/... -v`
Expected: PASS across the board.

- [ ] **Step 6: Commit**

```bash
git add cmd/daemon/main.go cmd/daemon/pkg/heavy-agent/event.go
git commit -m "feat(daemon): wire main.go to gRPC ControlClient/EventsClient, drop TCP EventProcessor"
```

---

### Task 10: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Full build**

Run: `go build ./cmd/daemon/...`
Expected: succeeds with no output.

- [ ] **Step 2: Full test run for every package touched in this plan**

Run: `go test ./cmd/daemon/pkg/heavy-agent/... ./cmd/daemon/pkg/microseg/... ./cmd/daemon/status/... -v`
Expected: every test PASSes; no test was skipped or left commented out.

- [ ] **Step 3: Confirm `pkg/waf` still builds untouched**

Run: `go build ./cmd/daemon/pkg/waf/...`
Expected: succeeds with no output (still references `*heavyagent.Client`, which Task 9 confirmed still exists in `client.go`).

- [ ] **Step 4: Lint the touched packages**

Run: `golangci-lint run ./cmd/daemon/pkg/heavy-agent/... ./cmd/daemon/pkg/microseg/... ./cmd/daemon/status/... ./cmd/daemon/...`
Expected: no new findings introduced by this plan's changes (pre-existing findings elsewhere in `cmd/daemon` are out of scope).

- [ ] **Step 5: Confirm no stray references to the deleted `EventProcessor` or removed types remain**

Run: `grep -rn "EventProcessor\|ConfigDumpReq\|ConfigDumpResp\b" cmd/daemon --include="*.go"`
Expected: no output.

- [ ] **Step 6: Final commit if Step 4 required fixes**

```bash
git add -A
git commit -m "chore(daemon): lint fixes for heavy-agent gRPC migration"
```

(Skip this step if Step 4 found nothing to fix.)
