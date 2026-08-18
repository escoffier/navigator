# Microseg NetworkPolicyRuleGroup gRPC Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the k8s-CRD-watch transport clustermanager and daemon use today to sync `NetworkPolicyRuleGroup` data with a direct push over the gRPC stream (`pkg/streaming`, package `rpcstream`) they already share, gated behind `MICROSEG_GRPC_ENABLED`.

**Architecture:** clustermanager keeps computing rule groups from `ClusterNetworkPolicy` exactly as today; only the sink changes, from `clientset.NetworkPolicyRuleGroups().Create/Update/Delete()` to a push over the existing in-cluster gRPC stream, targeted per-node via the `"<nodeName>-daemon"` key convention already used for `ComplianceScanReq`/`NodeLoadReq`. Daemon's `RuleGroupController` gets its rule groups from a small in-memory cache fed by that stream instead of a k8s informer/lister; a new gRPC `OnConnect` hook on the shared streaming framework lets clustermanager push a full bootstrap snapshot the moment a daemon (re)connects, replacing the implicit full-List a k8s informer gets for free. All existing rule-computation, rule-diffing, and local-net-policy-push logic (`generateRules`, `syncPolicyRules`'s diff, `buildPolicyRuleMessage*`, `syncPolicy`, `checkSync`, `splitPolicyRules`) is reused completely unmodified on both sides — it's isolated behind a same-shaped Go interface (`List`/`Get`, matching the generated k8s lister) so it can't tell whether it's reading from k8s or from the stream cache.

**Tech Stack:** Go, gRPC (`google.golang.org/grpc`), protobuf (`google.golang.org/protobuf`), the repo's existing `pkg/streaming` (`rpcstream`) bidirectional-stream framework, `k8s.io/apimachinery` (`labels`, `api/errors`) for lister-compatible semantics, `go test` + `bufconn`/manual fakes for tests (no live k8s/gRPC server needed).

**Spec:** `docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md` — read it alongside this plan. Two corrections discovered during planning (fixed in the spec, noted here so both documents agree):
1. Bootstrap-on-connect **cannot** be implemented as an `AddHandler(&pb.Register{}, ...)` handler — `messageStreamServer.SendMessage` (`pkg/streaming/streamfactory.go`) consumes the first (`Register`) message directly via `stream.Recv()` before the handler-dispatch loop (`Dispatch()`) even starts, so a `Register` handler registered via `AddHandler` is never invoked. Task 2 below adds a dedicated `OnConnect` extension point to the framework instead.
2. Clustermanager has no existing in-memory store of "current rule-group state" to reuse for bootstrap snapshots — `cmd/clustermanager/pkg/microseg/store.go`'s `NewRuleStore`/`NewPolicyStore` are unused dead code (confirmed via repo-wide grep). The actual mechanism `syncPolicyRules` uses today to know "what's out there" is reading back its own CRD writes via the k8s informer lister (`npc.ruleGroupLister`). Task 9 below adds a small new in-memory cache to replace that role.

## Global Constraints

- Feature flag `MICROSEG_GRPC_ENABLED` must be set identically on **both** clustermanager and daemon for a given cluster — they move in lockstep. Unset/false ⇒ today's CRD/informer path, byte-for-byte unchanged. `true` ⇒ gRPC-push path only, no CRD read or write at all (no hybrid/dual-write state).
- Node addressing convention: `"<nodeName>-daemon"`, matching `ComplianceScanReq`/`NodeLoadReq` (`cmd/console/service/scapper/compliance.go:48,156`). Reuse it verbatim — do not invent a new convention.
- All rule-group pushes are fire-and-forget (`ack=false` on `Request()`), matching today's un-acked CRD write — do not add response-waiting/retry semantics not already scoped here.
- Existing rule-computation and local-agent-push logic (`generateRules`, `syncPolicyRules`'s diff loop, `buildPolicyRuleMessage`, `buildPolicyRuleMessages`, `buildPolicyRuleMessages1`, `syncPolicy`, `checkSync`, `Run`, `ReSyncAllPolicy`, `splitPolicyRules`) must NOT be modified in this plan except where a task explicitly says so (narrow interface swaps only) — these are proven, non-goal code paths.
- Follow repo lint/format conventions: `golangci-lint run ./...`, `goimports` local-prefix `gitlab.com/piccolo_su/vegeta` (see root `CLAUDE.md`).
- New Go files go in the same package as the file they support (`package microseg` in both `cmd/daemon/pkg/microseg` and `cmd/clustermanager/pkg/microseg`; `package rpcstream` in `pkg/streaming`) — no new packages.

---

## Task 1: Proto — new `NetworkPolicyRuleGroup*` messages

**Files:**
- Create: `pkg/streaming/pb/microseg.proto`
- Modify: `pkg/streaming/pb/gen.sh`
- Test: `pkg/streaming/pb/microseg_roundtrip_test.go`

**Interfaces:**
- Produces: `pb.NetworkPolicyRuleGroupPayload`, `pb.MicrosegNodeRule`, `pb.MicrosegPort`, `pb.MicrosegAddress`, `pb.MicrosegIPBlock`, `pb.MicrosegHttp`, `pb.NetworkPolicyRuleGroupReq{RuleGroup *NetworkPolicyRuleGroupPayload}`, `pb.NetworkPolicyRuleGroupSyncReq{RuleGroups []*NetworkPolicyRuleGroupPayload}`, `pb.NetworkPolicyRuleGroupResp{Success bool, Error string}` (defined for symmetry with other message pairs in this package; unused by the fire-and-forget push path added in Task 3, kept for future acked use). Every later task in this plan imports these from `gitlab.com/piccolo_su/vegeta/pkg/streaming/pb`.

- [ ] **Step 1: Write `microseg.proto`**

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
    string Protocol = 1;
    string Port = 2;
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
    string Name = 1;
    string Policy = 2;
    string NodeName = 3;
    repeated MicrosegNodeRule Rules = 4;
}

message NetworkPolicyRuleGroupReq {
    NetworkPolicyRuleGroupPayload RuleGroup = 1;
}

message NetworkPolicyRuleGroupSyncReq {
    repeated NetworkPolicyRuleGroupPayload RuleGroups = 1;
}

message NetworkPolicyRuleGroupResp {
    bool Success = 1;
    string Error = 2;
}
```

- [ ] **Step 2: Enable it in `gen.sh` and regenerate**

Edit `pkg/streaming/pb/gen.sh` to add a line (keep the existing commented lines as-is, matching the file's current style of selectively enabling entries):

```bash
protoc  -I=./ --go-grpc_out=require_unimplemented_servers=false:. --go_out=. microseg.proto
```

Run from `pkg/streaming/pb/`:

```bash
cd pkg/streaming/pb && bash gen.sh
```

Expected: `microseg.pb.go` is generated in `pkg/streaming/pb/` (no `_grpc.pb.go` since the file defines no `service`). Confirm it compiles: `go build ./pkg/streaming/...` from the repo root.

- [ ] **Step 3: Write the round-trip test**

```go
package pb

import "testing"

func TestNetworkPolicyRuleGroupPayload_RoundTrip(t *testing.T) {
	protocol := "TCP"
	payload := &NetworkPolicyRuleGroupPayload{
		Name:     "policy-node1",
		Policy:   "policy",
		NodeName: "node1",
		Rules: []*MicrosegNodeRule{{
			Name:      "rule1",
			Priority:  100,
			Protocol:  "TCP",
			Direction: "ingress",
			Action:    "Allow",
			Ports:     []*MicrosegPort{{Protocol: protocol, Port: "80", EndPort: 0}},
			ToAddresses: []*MicrosegAddress{{IP: "10.0.0.2", PodNamespace: "ns", PodName: "pod"}},
			FromIPBlock: []*MicrosegIPBlock{{CIDR: "10.0.0.0/24"}},
			Http:        &MicrosegHttp{Method: "GET", Path: "/", Host: "example.com"},
		}},
	}

	data, err := proto.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := &NetworkPolicyRuleGroupPayload{}
	if err := proto.Unmarshal(data, got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.GetNodeName() != "node1" || len(got.GetRules()) != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.GetRules()[0].GetHttp().GetHost() != "example.com" {
		t.Fatalf("Http field lost in round-trip: %+v", got.GetRules()[0])
	}
}
```

Add the missing import (`"google.golang.org/protobuf/proto"`) to the top of the test file.

- [ ] **Step 4: Run the test**

Run: `go test ./pkg/streaming/pb/... -run TestNetworkPolicyRuleGroupPayload_RoundTrip -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/streaming/pb/microseg.proto pkg/streaming/pb/microseg.pb.go pkg/streaming/pb/gen.sh pkg/streaming/pb/microseg_roundtrip_test.go
git commit -m "feat(streaming): add NetworkPolicyRuleGroup proto messages"
```

---

## Task 2: `pkg/streaming` — add an `OnConnect` extension point

**Files:**
- Modify: `pkg/streaming/streamfactory.go`
- Test: `pkg/streaming/onconnect_test.go`

**Interfaces:**
- Consumes: nothing new (pure framework addition).
- Produces: `MessageStream.OnConnect(f func(nodeKey string))` — registers a callback invoked (in its own goroutine) whenever a new peer connects and sends its `Register` message. Task 10 (clustermanager) uses this to push the bootstrap rule-group snapshot.

- [ ] **Step 1: Write the failing test**

This exercises `messageStreamServer.SendMessage` directly against a fake `pb.ClusterService_SendMessageServer`, without a real network listener (mirrors how `NewServerStream` is unit-testable — it only needs something satisfying the gRPC stream interface).

```go
package rpcstream

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

type fakeSendMessageServer struct {
	mu       sync.Mutex
	recvOnce sync.Once
	sent     []*pb.ClusterMessage
	closed   chan struct{}
}

func newFakeSendMessageServer() *fakeSendMessageServer {
	return &fakeSendMessageServer{closed: make(chan struct{})}
}

func (f *fakeSendMessageServer) Send(m *pb.ClusterMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeSendMessageServer) Recv() (*pb.ClusterMessage, error) {
	<-f.closed
	return nil, io.EOF
}

func (f *fakeSendMessageServer) Context() context.Context             { return context.Background() }
func (f *fakeSendMessageServer) SendMsg(m interface{}) error          { return nil }
func (f *fakeSendMessageServer) RecvMsg(m interface{}) error          { return nil }
func (f *fakeSendMessageServer) SetHeader(metadata.MD) error          { return nil }
func (f *fakeSendMessageServer) SendHeader(metadata.MD) error         { return nil }
func (f *fakeSendMessageServer) SetTrailer(metadata.MD)               {}

func Test_OnConnect_FiresWithConnectingNodeKey(t *testing.T) {
	f := &streamFactory{}
	srv := f.Server("tcp", ":0").(*messageStreamServer)

	got := make(chan string, 1)
	srv.OnConnect(func(nodeKey string) {
		got <- nodeKey
	})

	fake := newFakeSendMessageServer()
	go func() {
		_ = srv.SendMessage(&registerOnceStream{fakeSendMessageServer: fake, nodeKey: "node1-daemon"})
	}()

	select {
	case nodeKey := <-got:
		if nodeKey != "node1-daemon" {
			t.Fatalf("OnConnect nodeKey = %q, want %q", nodeKey, "node1-daemon")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnConnect callback did not fire")
	}
	close(fake.closed)
}

// registerOnceStream wraps fakeSendMessageServer so the first Recv() returns a
// Register ClusterMessage (as a real client does on connect), then behaves like
// the fake for everything after.
type registerOnceStream struct {
	*fakeSendMessageServer
	nodeKey string
	sentReg bool
	mu      sync.Mutex
}

func (r *registerOnceStream) Recv() (*pb.ClusterMessage, error) {
	r.mu.Lock()
	if !r.sentReg {
		r.sentReg = true
		r.mu.Unlock()
		payload, _ := anypb.New(&pb.Register{NodeKey: r.nodeKey})
		return &pb.ClusterMessage{NodeKey: r.nodeKey, MessageType: pb.MessageType_CREATE, Payload: payload}, nil
	}
	r.mu.Unlock()
	return r.fakeSendMessageServer.Recv()
}
```

Add the import `"google.golang.org/protobuf/types/known/anypb"` to the test file (`pb.Register` already satisfies `proto.Message`/`protoreflect.ProtoMessage`, so `anypb.New` takes it directly — no extra wrapper needed).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/streaming/... -run Test_OnConnect_FiresWithConnectingNodeKey -v`
Expected: FAIL — `srv.OnConnect` undefined (method doesn't exist yet).

- [ ] **Step 3: Implement `OnConnect`**

In `pkg/streaming/streamfactory.go`:

1. Add a field to `messageStream` (the struct embedded by both `messageStreamServer` and `messageStreamClient`):

```go
type messageStream struct {
	streams    map[string]Stream
	processors map[string]ProcessFunc
	hanlders   map[string]MessageHandler
	KeyToLabel map[string]string
	noderKey   string
	Label      string
	streamLock sync.Mutex
	onConnect  func(nodeKey string)
}
```

2. Add the method (promoted to both server and client via the embedded struct):

```go
func (s *messageStream) OnConnect(f func(nodeKey string)) {
	s.streamLock.Lock()
	defer s.streamLock.Unlock()
	s.onConnect = f
}
```

3. Add it to the `MessageStream` interface:

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

4. Fire it in `messageStreamServer.SendMessage`, right after the stream is registered and its `Run` loop started:

```go
	s.streamLock.Lock()
	s.streams[in.NodeKey] = rs
	for name, fun := range s.processors {
		s.streams[in.NodeKey].AddHandlerFunc(name, fun)
	}
	for name, handler := range s.hanlders {
		s.streams[in.NodeKey].AddHandler(name, handler)
	}
	onConnect := s.onConnect
	s.streamLock.Unlock()

	go rs.Run(stopChan)

	if onConnect != nil {
		go onConnect(in.NodeKey)
	}

	logging.Get().Info().Msg("begin dispatching message")
	rs.Dispatch()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/streaming/... -run Test_OnConnect_FiresWithConnectingNodeKey -v`
Expected: PASS

- [ ] **Step 5: Check for regressions (scoped — do not run the bare package)**

**Do not run a bare `go test ./pkg/streaming/...`.** The pre-existing `Test_channel` in
`streamfactory_test.go` ends with an unconditional `select {}` and blocks forever; a bare
package-wide run hangs for ~10 minutes and then reports FAIL, unrelated to this task. Confirmed
present at this plan's baseline commit, before any change in this plan — out of scope to fix here.

Instead run:
```
go test ./pkg/streaming/... -run 'Test_OnConnect_FiresWithConnectingNodeKey|Test_messageStream_Request'
go build ./pkg/streaming/...
```
Expected: the `-run` invocation PASSes (covers this task's new test plus the pre-existing, already-passing
`Test_messageStream_Request` scaffold — its table is empty so it trivially passes); the `go build` succeeds.

- [ ] **Step 6: Commit**

```bash
git add pkg/streaming/streamfactory.go pkg/streaming/onconnect_test.go
git commit -m "feat(streaming): add OnConnect hook for peer-connect callbacks"
```

---

## Task 3: `pkg/streaming` — `PushRuleGroup`/`PushRuleGroupSync` client methods

**Files:**
- Modify: `pkg/streaming/client.go`
- Test: `pkg/streaming/rulegroup_client_test.go`

**Interfaces:**
- Consumes: `pb.NetworkPolicyRuleGroupReq`, `pb.NetworkPolicyRuleGroupSyncReq` (Task 1).
- Produces: added to `MessageStreamClient`: `PushRuleGroup(ctx context.Context, nodeKey string, msgType pb.MessageType, req *pb.NetworkPolicyRuleGroupReq) error` and `PushRuleGroupSync(ctx context.Context, nodeKey string, req *pb.NetworkPolicyRuleGroupSyncReq) error`. Task 9's `grpcRuleGroupPusher` and Task 10's `RegisterOnConnect` call these.

- [ ] **Step 1: Write the failing test**

This uses the same "construct a bare `messageStream` with a fake `Stream` wired into `s.streams`" approach the existing (empty) `Test_messageStream_Request` scaffolds for — but actually implemented, with a minimal fake `Stream`.

```go
package rpcstream

import (
	"context"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

type fakeStream struct {
	sent []*pb.ClusterMessage
}

func (f *fakeStream) Dispatch() error                                         { return nil }
func (f *fakeStream) AddHandler(string, MessageHandler) error                 { return nil }
func (f *fakeStream) AddHandlerFunc(string, ProcessFunc) error                { return nil }
func (f *fakeStream) AddSession(id string, ack bool)                          {}
func (f *fakeStream) DelSession(id string)                                    {}
func (f *fakeStream) DelAllSession()                                          {}
func (f *fakeStream) Send(m *pb.ClusterMessage) error {
	f.sent = append(f.sent, m)
	return nil
}
func (f *fakeStream) Response(ctx context.Context, reqUUID string) (protoreflect.ProtoMessage, error) {
	return nil, nil
}
func (f *fakeStream) SendResponse(string, protoreflect.ProtoMessage) error { return nil }
func (f *fakeStream) Run(stopChan chan struct{})                          {}
func (f *fakeStream) Dump() map[string]interface{}                        { return nil }
func (f *fakeStream) Clean()                                              {}

func Test_messageStream_PushRuleGroup(t *testing.T) {
	fs := &fakeStream{}
	s := &messageStream{streams: map[string]Stream{"node1-daemon": fs}}

	req := &pb.NetworkPolicyRuleGroupReq{RuleGroup: &pb.NetworkPolicyRuleGroupPayload{Name: "policy-node1"}}
	if err := s.PushRuleGroup(context.Background(), "node1-daemon", pb.MessageType_CREATE, req); err != nil {
		t.Fatalf("PushRuleGroup: %v", err)
	}
	if len(fs.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(fs.sent))
	}
	if fs.sent[0].MessageType != pb.MessageType_CREATE {
		t.Errorf("MessageType = %v, want CREATE", fs.sent[0].MessageType)
	}
	got, err := fs.sent[0].Payload.UnmarshalNew()
	if err != nil {
		t.Fatalf("UnmarshalNew: %v", err)
	}
	gotReq, ok := got.(*pb.NetworkPolicyRuleGroupReq)
	if !ok || gotReq.GetRuleGroup().GetName() != "policy-node1" {
		t.Errorf("payload = %+v, want RuleGroup.Name=policy-node1", got)
	}
}

func Test_messageStream_PushRuleGroup_UnknownNode(t *testing.T) {
	s := &messageStream{streams: map[string]Stream{}}
	req := &pb.NetworkPolicyRuleGroupReq{RuleGroup: &pb.NetworkPolicyRuleGroupPayload{Name: "policy-node1"}}
	if err := s.PushRuleGroup(context.Background(), "missing-daemon", pb.MessageType_CREATE, req); err == nil {
		t.Fatal("PushRuleGroup: want error for unknown node, got nil")
	}
}

func Test_messageStream_PushRuleGroupSync(t *testing.T) {
	fs := &fakeStream{}
	s := &messageStream{streams: map[string]Stream{"node1-daemon": fs}}

	req := &pb.NetworkPolicyRuleGroupSyncReq{RuleGroups: []*pb.NetworkPolicyRuleGroupPayload{{Name: "a"}, {Name: "b"}}}
	if err := s.PushRuleGroupSync(context.Background(), "node1-daemon", req); err != nil {
		t.Fatalf("PushRuleGroupSync: %v", err)
	}
	if len(fs.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(fs.sent))
	}
	got, err := fs.sent[0].Payload.UnmarshalNew()
	if err != nil {
		t.Fatalf("UnmarshalNew: %v", err)
	}
	gotReq, ok := got.(*pb.NetworkPolicyRuleGroupSyncReq)
	if !ok || len(gotReq.GetRuleGroups()) != 2 {
		t.Errorf("payload = %+v, want 2 rule groups", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/streaming/... -run Test_messageStream_PushRuleGroup -v`
Expected: FAIL — `s.PushRuleGroup`/`s.PushRuleGroupSync` undefined.

- [ ] **Step 3: Implement**

Add to the `MessageStreamClient` interface in `pkg/streaming/client.go`:

```go
	// PushRuleGroup 推送 NetworkPolicyRuleGroup 增量事件到指定节点
	PushRuleGroup(ctx context.Context, nodeKey string, msgType pb.MessageType, req *pb.NetworkPolicyRuleGroupReq) error

	// PushRuleGroupSync 推送节点重连时的全量快照
	PushRuleGroupSync(ctx context.Context, nodeKey string, req *pb.NetworkPolicyRuleGroupSyncReq) error
```

Add the implementations (append to `pkg/streaming/client.go`, matching `PushComplianceScan`'s style but fire-and-forget per the Global Constraints):

```go
func (s *messageStream) PushRuleGroup(ctx context.Context, nodeKey string, msgType pb.MessageType, req *pb.NetworkPolicyRuleGroupReq) error {
	_, err := s.Request(ctx, nodeKey, msgType, req, false)
	if err != nil {
		logging.Get().Err(err).Str("nodeKey", nodeKey).Msg("failed to push rule group msg")
		return err
	}
	return nil
}

func (s *messageStream) PushRuleGroupSync(ctx context.Context, nodeKey string, req *pb.NetworkPolicyRuleGroupSyncReq) error {
	_, err := s.Request(ctx, nodeKey, pb.MessageType_CREATE, req, false)
	if err != nil {
		logging.Get().Err(err).Str("nodeKey", nodeKey).Msg("failed to push rule group sync msg")
		return err
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/streaming/... -run Test_messageStream_PushRuleGroup -v`
Expected: PASS (all three test functions)

- [ ] **Step 5: Commit**

```bash
git add pkg/streaming/client.go pkg/streaming/rulegroup_client_test.go
git commit -m "feat(streaming): add PushRuleGroup/PushRuleGroupSync client methods"
```

---

## Task 4: Daemon — proto↔CRD-struct adapter

**Files:**
- Create: `cmd/daemon/pkg/microseg/rulegroup_payload.go`
- Test: `cmd/daemon/pkg/microseg/rulegroup_payload_test.go`

**Interfaces:**
- Consumes: `pb.NetworkPolicyRuleGroupPayload` and friends (Task 1).
- Produces: `payloadToRuleGroup(payload *pb.NetworkPolicyRuleGroupPayload) *crdv1alpha1.NetworkPolicyRuleGroup`. Task 6's stream handlers call this; its output feeds the **unchanged** `buildPolicyRuleMessage`/`buildPolicyRuleMessages`/`buildPolicyRuleMessages1`/`syncPolicy`/`checkSync`/`splitPolicyRules` functions in `cmd/daemon/pkg/microseg/policyrule_controller.go` — this is the crux of why those functions need zero edits.

- [ ] **Step 1: Write the failing test**

```go
package microseg

import (
	"testing"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

func Test_payloadToRuleGroup(t *testing.T) {
	payload := &pb.NetworkPolicyRuleGroupPayload{
		Name:     "policy-node1",
		Policy:   "policy",
		NodeName: "node1",
		Rules: []*pb.MicrosegNodeRule{{
			Name:      "rule1",
			Priority:  100,
			Protocol:  "TCP",
			Direction: "ingress",
			Action:    "Allow",
			Ports:     []*pb.MicrosegPort{{Protocol: "TCP", Port: "80", EndPort: 90}},
			FromAddress: []*pb.MicrosegAddress{{IP: "10.0.0.1", PodNamespace: "ns", PodName: "pod-a"}},
			ToAddresses: []*pb.MicrosegAddress{{IP: "10.0.0.2"}},
			FromIPBlock: []*pb.MicrosegIPBlock{{CIDR: "10.0.1.0/24"}},
			ToIPBlock:   []*pb.MicrosegIPBlock{{CIDR: "10.0.2.0/24"}},
			Http:        &pb.MicrosegHttp{Method: "GET", Path: "/health", Host: "svc"},
		}},
	}

	rg := payloadToRuleGroup(payload)

	if rg.Name != "policy-node1" {
		t.Errorf("Name = %q, want %q", rg.Name, "policy-node1")
	}
	if rg.Spec.Policy != "policy" || rg.Spec.NodeName != "node1" {
		t.Errorf("Spec = %+v, want Policy=policy NodeName=node1", rg.Spec)
	}
	if len(rg.Spec.Rules) != 1 {
		t.Fatalf("Rules = %d, want 1", len(rg.Spec.Rules))
	}
	r := rg.Spec.Rules[0]
	if r.Name != "rule1" || r.Priority != 100 || r.Action != "Allow" || r.Direction != "ingress" {
		t.Errorf("rule fields mismatch: %+v", r)
	}
	if len(r.Ports) != 1 || r.Ports[0].Protocol == nil || string(*r.Ports[0].Protocol) != "TCP" {
		t.Fatalf("Ports mismatch: %+v", r.Ports)
	}
	if r.Ports[0].Port == nil || r.Ports[0].Port.String() != "80" {
		t.Errorf("Port = %v, want 80", r.Ports[0].Port)
	}
	if r.Ports[0].EndPort == nil || *r.Ports[0].EndPort != 90 {
		t.Errorf("EndPort = %v, want 90", r.Ports[0].EndPort)
	}
	if len(r.FromAddress) != 1 || r.FromAddress[0].IP != "10.0.0.1" || r.FromAddress[0].PodReference == nil ||
		r.FromAddress[0].PodReference.Namespace != "ns" || r.FromAddress[0].PodReference.Name != "pod-a" {
		t.Errorf("FromAddress mismatch: %+v", r.FromAddress)
	}
	if len(r.ToAddresses) != 1 || r.ToAddresses[0].IP != "10.0.0.2" || r.ToAddresses[0].PodReference != nil {
		t.Errorf("ToAddresses mismatch: %+v", r.ToAddresses)
	}
	if len(r.FromIPBlock) != 1 || r.FromIPBlock[0].CIDR != "10.0.1.0/24" {
		t.Errorf("FromIPBlock mismatch: %+v", r.FromIPBlock)
	}
	if len(r.ToIPBlock) != 1 || r.ToIPBlock[0].CIDR != "10.0.2.0/24" {
		t.Errorf("ToIPBlock mismatch: %+v", r.ToIPBlock)
	}
	if r.Http == nil || r.Http.Host != "svc" || r.Http.Path != "/health" || r.Http.Method != "GET" {
		t.Errorf("Http mismatch: %+v", r.Http)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/daemon/pkg/microseg/... -run Test_payloadToRuleGroup -v`
Expected: FAIL — `payloadToRuleGroup` undefined.

- [ ] **Step 3: Implement**

```go
package microseg

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

// payloadToRuleGroup adapts a gRPC-pushed rule group payload back into the
// existing crdv1alpha1.NetworkPolicyRuleGroup shape, so buildPolicyRuleMessage*/
// syncPolicy/checkSync/splitPolicyRules (written against the k8s CRD) keep
// working unmodified regardless of whether the data came from a k8s informer
// or this stream-based transport.
func payloadToRuleGroup(payload *pb.NetworkPolicyRuleGroupPayload) *crdv1alpha1.NetworkPolicyRuleGroup {
	rg := &crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: payload.GetName()},
		Spec: crdv1alpha1.NetworkPolicyRuleGroupSpec{
			Policy:   payload.GetPolicy(),
			NodeName: payload.GetNodeName(),
		},
	}
	for _, r := range payload.GetRules() {
		rg.Spec.Rules = append(rg.Spec.Rules, payloadToNodeRule(r))
	}
	return rg
}

func payloadToNodeRule(r *pb.MicrosegNodeRule) crdv1alpha1.NodeRule {
	out := crdv1alpha1.NodeRule{
		Name:      r.GetName(),
		Priority:  int(r.GetPriority()),
		Protocol:  r.GetProtocol(),
		Direction: r.GetDirection(),
		Action:    r.GetAction(),
	}
	for _, p := range r.GetPorts() {
		port := crdv1alpha1.NetworkPolicyPort{}
		if p.GetProtocol() != "" {
			proto := crdv1alpha1.Protocol(p.GetProtocol())
			port.Protocol = &proto
		}
		if p.GetPort() != "" {
			v := intstr.Parse(p.GetPort())
			port.Port = &v
		}
		if p.GetEndPort() != 0 {
			endPort := p.GetEndPort()
			port.EndPort = &endPort
		}
		out.Ports = append(out.Ports, port)
	}
	for _, a := range r.GetToAddresses() {
		out.ToAddresses = append(out.ToAddresses, payloadToAddress(a))
	}
	for _, b := range r.GetToIPBlock() {
		out.ToIPBlock = append(out.ToIPBlock, crdv1alpha1.IPBlock{CIDR: b.GetCIDR()})
	}
	for _, a := range r.GetFromAddress() {
		out.FromAddress = append(out.FromAddress, payloadToAddress(a))
	}
	for _, b := range r.GetFromIPBlock() {
		out.FromIPBlock = append(out.FromIPBlock, crdv1alpha1.IPBlock{CIDR: b.GetCIDR()})
	}
	if r.GetHttp() != nil {
		out.Http = &crdv1alpha1.Http{Method: r.GetHttp().GetMethod(), Path: r.GetHttp().GetPath(), Host: r.GetHttp().GetHost()}
	}
	return out
}

func payloadToAddress(a *pb.MicrosegAddress) crdv1alpha1.Address {
	out := crdv1alpha1.Address{IP: a.GetIP()}
	if a.GetPodName() != "" || a.GetPodNamespace() != "" {
		out.PodReference = &crdv1alpha1.EntityReference{
			Namespace: a.GetPodNamespace(),
			Name:      a.GetPodName(),
		}
	}
	return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/daemon/pkg/microseg/... -run Test_payloadToRuleGroup -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/daemon/pkg/microseg/rulegroup_payload.go cmd/daemon/pkg/microseg/rulegroup_payload_test.go
git commit -m "feat(daemon/microseg): adapt gRPC rule group payload to CRD struct"
```

---

## Task 5: Daemon — stream-backed rule group cache

**Files:**
- Create: `cmd/daemon/pkg/microseg/rulegroup_cache.go`
- Test: `cmd/daemon/pkg/microseg/rulegroup_cache_test.go`

**Interfaces:**
- Consumes: `crdv1alpha1.NetworkPolicyRuleGroup` (produced by Task 4's adapter).
- Produces: `ruleGroupLister` interface (`List(labels.Selector) ([]*crdv1alpha1.NetworkPolicyRuleGroup, error)`, `Get(name string) (*crdv1alpha1.NetworkPolicyRuleGroup, error)`) and `*streamRuleCache` implementing it plus `Set`, `Delete`, `ReplaceAll(all []*crdv1alpha1.NetworkPolicyRuleGroup) (removed []string)`. Task 6's handlers call `Set`/`Delete`/`ReplaceAll`; Task 7's `NewStreamRuleGroupController` assigns a `*streamRuleCache` to `RuleGroupController.ruleLister` (declared as this interface).

- [ ] **Step 1: Write the failing test**

```go
package microseg

import (
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

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
```

Add a small test helper at the top of the test file (avoids repeating `v1.ObjectMeta{Name: ...}` and importing `metav1` under a different alias than production code uses):

```go
import v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

func v1ObjectMeta(name string) v1.ObjectMeta {
	return v1.ObjectMeta{Name: name}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/daemon/pkg/microseg/... -run Test_streamRuleCache -v`
Expected: FAIL — `newStreamRuleCache` undefined.

- [ ] **Step 3: Implement**

```go
package microseg

import (
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

// ruleGroupLister is the subset of the generated NetworkPolicyRuleGroupLister
// that RuleGroupController depends on. A *streamRuleCache implements it too,
// so RuleGroupController's Run/syncPolicy/ReSyncAllPolicy/checkSync logic
// (written against the k8s-informer lister) works unmodified against either
// transport.
type ruleGroupLister interface {
	List(selector labels.Selector) ([]*crdv1alpha1.NetworkPolicyRuleGroup, error)
	Get(name string) (*crdv1alpha1.NetworkPolicyRuleGroup, error)
}

// streamRuleCache holds the rule groups most recently pushed over gRPC by
// clustermanager, replacing the k8s informer cache as RuleGroupController's
// source of "current state".
type streamRuleCache struct {
	mu     sync.RWMutex
	byName map[string]*crdv1alpha1.NetworkPolicyRuleGroup
}

func newStreamRuleCache() *streamRuleCache {
	return &streamRuleCache{byName: make(map[string]*crdv1alpha1.NetworkPolicyRuleGroup)}
}

func (c *streamRuleCache) Set(rg *crdv1alpha1.NetworkPolicyRuleGroup) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byName[rg.Name] = rg
}

func (c *streamRuleCache) Delete(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byName, name)
}

func (c *streamRuleCache) Get(name string) (*crdv1alpha1.NetworkPolicyRuleGroup, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rg, ok := c.byName[name]
	if !ok {
		return nil, apierrors.NewNotFound(crdv1alpha1.Resource("networkpolicyrulegroup"), name)
	}
	return rg, nil
}

func (c *streamRuleCache) List(selector labels.Selector) ([]*crdv1alpha1.NetworkPolicyRuleGroup, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*crdv1alpha1.NetworkPolicyRuleGroup
	for _, rg := range c.byName {
		if selector == nil || selector.Matches(labels.Set(rg.Labels)) {
			out = append(out, rg)
		}
	}
	return out, nil
}

// ReplaceAll atomically swaps the cache contents with a fresh bootstrap
// snapshot, returning the names that were present before but are absent from
// the new snapshot (the caller must enqueue these for deletion so state
// converges correctly after a reconnect).
func (c *streamRuleCache) ReplaceAll(all []*crdv1alpha1.NetworkPolicyRuleGroup) (removed []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	newMap := make(map[string]*crdv1alpha1.NetworkPolicyRuleGroup, len(all))
	for _, rg := range all {
		newMap[rg.Name] = rg
	}
	for name := range c.byName {
		if _, ok := newMap[name]; !ok {
			removed = append(removed, name)
		}
	}
	c.byName = newMap
	return removed
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/daemon/pkg/microseg/... -run Test_streamRuleCache -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/daemon/pkg/microseg/rulegroup_cache.go cmd/daemon/pkg/microseg/rulegroup_cache_test.go
git commit -m "feat(daemon/microseg): add stream-backed rule group cache"
```

---

## Task 6: Daemon — stream handlers + controller wiring

**Files:**
- Modify: `cmd/daemon/pkg/microseg/policyrule_controller.go`
- Create: `cmd/daemon/pkg/microseg/rulegroup_stream_handler.go`
- Test: `cmd/daemon/pkg/microseg/rulegroup_stream_handler_test.go`

**Interfaces:**
- Consumes: `payloadToRuleGroup` (Task 4), `*streamRuleCache`/`ruleGroupLister` (Task 5), `rpcstream.MessageHandler`/`rpcstream.Stream` (existing, `pkg/streaming`).
- Produces: `RuleGroupStreamHandler{Controller *RuleGroupController}` (implements `rpcstream.MessageHandler` for `pb.NetworkPolicyRuleGroupReq`), `RuleGroupSyncStreamHandler{Controller *RuleGroupController}` (implements it for `pb.NetworkPolicyRuleGroupSyncReq`), `NewStreamRuleGroupController(cli PolicyClient, nodeName string, mqWriter mq.Writer, agentCli *heavyagent.ControlClient) *RuleGroupController`. Task 8 registers these two handlers on the daemon's `rpcStream` in `main.go`.

- [ ] **Step 1: Modify `RuleGroupController`'s struct and add the stream constructor**

In `cmd/daemon/pkg/microseg/policyrule_controller.go`:

1. Change the `ruleLister` field's declared type from the generated `v1alpha1.NetworkPolicyRuleGroupLister` to the local `ruleGroupLister` interface (Task 5), and add two fields:

```go
type RuleGroupController struct {
	ruleInformer    cache.SharedIndexInformer
	ruleLister      ruleGroupLister
	ruleGroupSynced cache.InformerSynced
	queue           workqueue.RateLimitingInterface
	polCli          PolicyClient
	nodeName        string
	mqSender        mq.Writer
	agentCli        *heavyagent.ControlClient
	ruleMap         map[string]sets.String
	streamCache     *streamRuleCache
	synced          atomic.Bool
}
```

(`ruleGroupSynced cache.InformerSynced` is `func() bool` — unchanged type, just now also settable to a closure over `synced` for the stream path.)

Add `"sync/atomic"` to the imports.

2. `NewRuleGroupController` (the existing k8s-informer constructor) needs no logic changes — `crdFactory.Microsegmentation().V1alpha1().NetworkPolicyRuleGroups().Lister()` already satisfies the narrower `ruleGroupLister` interface structurally, so it still type-checks against the retyped field.

3. Add the new constructor, right after `NewRuleGroupController`:

```go
// NewStreamRuleGroupController builds a RuleGroupController fed by the
// daemon<->clustermanager gRPC stream instead of a k8s informer, used when
// MICROSEG_GRPC_ENABLED=true. Callers must register RuleGroupStreamHandler and
// RuleGroupSyncStreamHandler on the stream for the returned controller (see
// cmd/daemon/main.go).
func NewStreamRuleGroupController(cli PolicyClient, nodeName string, mqWriter mq.Writer, agentCli *heavyagent.ControlClient) *RuleGroupController {
	streamCache := newStreamRuleCache()
	controller := &RuleGroupController{
		ruleLister:  streamCache,
		streamCache: streamCache,
		queue:       workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "rulegroup-queue"),
		polCli:      cli,
		nodeName:    nodeName,
		mqSender:    mqWriter,
		agentCli:    agentCli,
		ruleMap:     make(map[string]sets.String),
	}
	controller.ruleGroupSynced = controller.synced.Load

	cli.AddReConnectionCallback(controller.ReSyncAllPolicy)
	return controller
}
```

- [ ] **Step 2: Write the failing test for the stream handlers**

```go
package microseg

import (
	"testing"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

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
	if !controller.synced.Load() {
		t.Fatal("synced flag not set after first snapshot")
	}
}
```

Add the shared fixture near the top of the test file:

```go
import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

var payloadRuleGroupFixture = crdv1alpha1.NetworkPolicyRuleGroup{
	ObjectMeta: v1.ObjectMeta{Name: "policy-node1"},
	Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{Policy: "policy", NodeName: "node1"},
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./cmd/daemon/pkg/microseg/... -run 'Test_RuleGroupStreamHandler|Test_RuleGroupSyncStreamHandler' -v`
Expected: FAIL — `RuleGroupStreamHandler`/`RuleGroupSyncStreamHandler` undefined.

- [ ] **Step 4: Implement the handlers**

Create `cmd/daemon/pkg/microseg/rulegroup_stream_handler.go`:

```go
package microseg

import (
	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/reflect/protoreflect"

	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

// RuleGroupStreamHandler receives NetworkPolicyRuleGroupReq pushes (single
// create/update/delete events) from clustermanager and feeds them into
// RuleGroupController, replacing the k8s informer event handlers
// (addRuleGroup/updateRuleGroup/deleteRuleGroup) used when
// MICROSEG_GRPC_ENABLED is unset.
type RuleGroupStreamHandler struct {
	Controller *RuleGroupController
}

func (h *RuleGroupStreamHandler) upsert(message protoreflect.ProtoMessage) {
	req, ok := message.(*pb.NetworkPolicyRuleGroupReq)
	if !ok {
		logging.Get().Error().Msg("RuleGroupStreamHandler: unexpected message type")
		return
	}
	rg := payloadToRuleGroup(req.GetRuleGroup())
	h.Controller.streamCache.Set(rg)
	h.Controller.queue.Add(rg.Name)
}

func (h *RuleGroupStreamHandler) OnCreate(_ rpcstream.Stream, _ string, message protoreflect.ProtoMessage) {
	h.upsert(message)
}

func (h *RuleGroupStreamHandler) OnUpdate(_ rpcstream.Stream, _ string, message protoreflect.ProtoMessage) {
	h.upsert(message)
}

func (h *RuleGroupStreamHandler) OnDelete(_ rpcstream.Stream, _ string, message protoreflect.ProtoMessage) {
	req, ok := message.(*pb.NetworkPolicyRuleGroupReq)
	if !ok {
		logging.Get().Error().Msg("RuleGroupStreamHandler: unexpected message type on delete")
		return
	}
	name := req.GetRuleGroup().GetName()
	h.Controller.streamCache.Delete(name)
	h.Controller.queue.Add(name)
}

func (h *RuleGroupStreamHandler) OnRead(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
	logging.Get().Error().Msg("RuleGroupStreamHandler: OnRead not implemented")
}

// RuleGroupSyncStreamHandler receives the full-snapshot bootstrap push sent
// once clustermanager sees this daemon (re)connect (see Task 10's OnConnect
// registration), the gRPC-push equivalent of the initial List a k8s informer
// gets for free.
type RuleGroupSyncStreamHandler struct {
	Controller *RuleGroupController
}

func (h *RuleGroupSyncStreamHandler) OnCreate(_ rpcstream.Stream, _ string, message protoreflect.ProtoMessage) {
	req, ok := message.(*pb.NetworkPolicyRuleGroupSyncReq)
	if !ok {
		logging.Get().Error().Msg("RuleGroupSyncStreamHandler: unexpected message type")
		return
	}
	var rgs []*crdv1alpha1.NetworkPolicyRuleGroup
	for _, payload := range req.GetRuleGroups() {
		rgs = append(rgs, payloadToRuleGroup(payload))
	}
	removed := h.Controller.streamCache.ReplaceAll(rgs)
	for _, name := range removed {
		h.Controller.queue.Add(name)
	}
	for _, rg := range rgs {
		h.Controller.queue.Add(rg.Name)
	}
	h.Controller.synced.Store(true)
}

func (h *RuleGroupSyncStreamHandler) OnRead(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage)   {}
func (h *RuleGroupSyncStreamHandler) OnUpdate(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {}
func (h *RuleGroupSyncStreamHandler) OnDelete(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./cmd/daemon/pkg/microseg/... -run 'Test_RuleGroupStreamHandler|Test_RuleGroupSyncStreamHandler' -v`
Expected: PASS

- [ ] **Step 6: Run the full daemon microseg package test suite**

Run: `go test ./cmd/daemon/pkg/microseg/...`
Expected: PASS (including pre-existing `policy_client_test.go`, `proto_mapping_test.go`, `event_mapping_test.go` — this task must not break them).

- [ ] **Step 7: Commit**

```bash
git add cmd/daemon/pkg/microseg/policyrule_controller.go cmd/daemon/pkg/microseg/rulegroup_stream_handler.go cmd/daemon/pkg/microseg/rulegroup_stream_handler_test.go
git commit -m "feat(daemon/microseg): add gRPC stream handlers and stream-based controller"
```

---

## Task 7: Daemon — wire `MICROSEG_GRPC_ENABLED` in `main.go`

**Files:**
- Modify: `cmd/daemon/main.go`

**Interfaces:**
- Consumes: `microseg.NewStreamRuleGroupController`, `microseg.RuleGroupStreamHandler`, `microseg.RuleGroupSyncStreamHandler` (Task 6), `rpcStream.AddHandler` (existing).

This task is wiring-only (no new logic to unit test); verify it with `go build` and the manual steps below.

- [ ] **Step 1: Locate and branch the existing wiring**

In `cmd/daemon/main.go`, inside the `if os.Getenv("MICROSEG_ENABLED") == "true" {` block (around line 414-459), the current rule-group wiring is:

```go
		tensorFactory := externalversions.NewSharedInformerFactoryWithOptions(clientset.TensorClientset, 10*time.Hour,
			externalversions.WithTweakListOptions(func(lo *v1.ListOptions) {
				lo.LabelSelector = fmt.Sprintf("kubernetes.io/node-name=%s", hostName)
			}))
		ruleController := microseg.NewRuleGroupController(clientset.TensorClientset, tensorFactory, policyClient, hostName, mqWriter, ctrlClient)

		go ruleController.Run(stopChan)
```

Replace it with a flag branch. `tensorFactory` stays created unconditionally, exactly where it is today (the WAF block later in this same function, `cmd/daemon/main.go:446-457`, also depends on it regardless of `MICROSEG_GRPC_ENABLED` — WAF is an unrelated, already-dead-per-`54ddff9d7` code path per the spec's Non-goals, so its dependency on `tensorFactory` must keep working unchanged). Only the k8s-informer-based `ruleController` construction is skipped when the flag is on:

```go
		tensorFactory := externalversions.NewSharedInformerFactoryWithOptions(clientset.TensorClientset, 10*time.Hour,
			externalversions.WithTweakListOptions(func(lo *v1.ListOptions) {
				lo.LabelSelector = fmt.Sprintf("kubernetes.io/node-name=%s", hostName)
			}))

		var ruleController *microseg.RuleGroupController
		if os.Getenv("MICROSEG_GRPC_ENABLED") == "true" {
			ruleController = microseg.NewStreamRuleGroupController(policyClient, hostName, mqWriter, ctrlClient)
			_ = rpcStream.AddHandler(&pb.NetworkPolicyRuleGroupReq{}, &microseg.RuleGroupStreamHandler{Controller: ruleController})
			_ = rpcStream.AddHandler(&pb.NetworkPolicyRuleGroupSyncReq{}, &microseg.RuleGroupSyncStreamHandler{Controller: ruleController})
		} else {
			ruleController = microseg.NewRuleGroupController(clientset.TensorClientset, tensorFactory, policyClient, hostName, mqWriter, ctrlClient)
		}

		go ruleController.Run(stopChan)
```

This keeps `tensorFactory`'s creation and the later `tensorFactory.Start(stopChan)` / `tensorFactory.WaitForCacheSync(stopChan)` calls (original lines 459-460) completely untouched — when the flag is on, `tensorFactory` is still created and started (needed for WAF, an orthogonal concern per the spec's Non-goals) but is simply never handed to a `NetworkPolicyRuleGroups()` lister/informer registration, so it carries no rule-group-CRD watch traffic either way once `NewStreamRuleGroupController` (which never touches `tensorFactory`) is used instead.

- [ ] **Step 2: Verify imports**

`pb "gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"` is already imported in `main.go` (used for `streampb`/`rpcstream` wiring at the top of `Run`) — confirm the existing import alias; if `main.go` already imports the daemon's own `cmd/daemon/pkg/heavy-agent/pb` under the name `pb`, the streaming package's `pb` must be imported under a different alias (e.g. `streampb "gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"`, matching the alias already used for `streampb.ComplianceScanReq`/`streampb.NodeLoadReq` at lines 358-359) — use `streampb.NetworkPolicyRuleGroupReq{}` / `streampb.NetworkPolicyRuleGroupSyncReq{}` in the `AddHandler` calls above instead of `pb.*` to match whichever alias is already in the file.

- [ ] **Step 3: Build**

Run: `CGO_ENABLED=1 go build -o /tmp/daemon-build-check ./cmd/daemon`
Expected: builds successfully (CGO is required for this binary per root `CLAUDE.md`).

- [ ] **Step 4: Commit**

```bash
git add cmd/daemon/main.go
git commit -m "feat(daemon): wire MICROSEG_GRPC_ENABLED rule group stream path"
```

---

## Task 8: Clustermanager — proto↔CRD-struct adapter (reverse direction)

**Files:**
- Create: `cmd/clustermanager/pkg/microseg/rulegroup_payload.go`
- Test: `cmd/clustermanager/pkg/microseg/rulegroup_payload_test.go`

**Interfaces:**
- Consumes: `crdv1alpha1.NetworkPolicyRuleGroup` (already produced by the unchanged `generateRules`/`caculatePolicyNodeRules*` functions).
- Produces: `ruleGroupToPayload(rg *crdv1alpha1.NetworkPolicyRuleGroup) *pb.NetworkPolicyRuleGroupPayload`. Task 9's `grpcRuleGroupPusher` and Task 10's `RegisterOnConnect` call this.

- [ ] **Step 1: Write the failing test**

```go
package microseg

import (
	"testing"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

func Test_ruleGroupToPayload(t *testing.T) {
	port := intstr.FromInt(80)
	protocol := crdv1alpha1.Protocol("TCP")
	endPort := int32(90)

	rg := &crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "policy-node1"},
		Spec: crdv1alpha1.NetworkPolicyRuleGroupSpec{
			Policy:   "policy",
			NodeName: "node1",
			Rules: []crdv1alpha1.NodeRule{{
				Name: "rule1", Priority: 100, Protocol: "TCP", Direction: "ingress", Action: "Allow",
				Ports:       []crdv1alpha1.NetworkPolicyPort{{Protocol: &protocol, Port: &port, EndPort: &endPort}},
				FromAddress: []crdv1alpha1.Address{{IP: "10.0.0.1", PodReference: &crdv1alpha1.EntityReference{Namespace: "ns", Name: "pod-a"}}},
				ToAddresses: []crdv1alpha1.Address{{IP: "10.0.0.2"}},
				FromIPBlock: []crdv1alpha1.IPBlock{{CIDR: "10.0.1.0/24"}},
				ToIPBlock:   []crdv1alpha1.IPBlock{{CIDR: "10.0.2.0/24"}},
				Http:        &crdv1alpha1.Http{Method: "GET", Path: "/health", Host: "svc"},
			}},
		},
	}

	payload := ruleGroupToPayload(rg)

	if payload.GetName() != "policy-node1" || payload.GetPolicy() != "policy" || payload.GetNodeName() != "node1" {
		t.Fatalf("payload fields mismatch: %+v", payload)
	}
	if len(payload.GetRules()) != 1 {
		t.Fatalf("Rules = %d, want 1", len(payload.GetRules()))
	}
	r := payload.GetRules()[0]
	if r.GetName() != "rule1" || r.GetPriority() != 100 || r.GetAction() != "Allow" {
		t.Errorf("rule fields mismatch: %+v", r)
	}
	if len(r.GetPorts()) != 1 || r.GetPorts()[0].GetProtocol() != "TCP" || r.GetPorts()[0].GetPort() != "80" || r.GetPorts()[0].GetEndPort() != 90 {
		t.Errorf("Ports mismatch: %+v", r.GetPorts())
	}
	if len(r.GetFromAddress()) != 1 || r.GetFromAddress()[0].GetIP() != "10.0.0.1" ||
		r.GetFromAddress()[0].GetPodNamespace() != "ns" || r.GetFromAddress()[0].GetPodName() != "pod-a" {
		t.Errorf("FromAddress mismatch: %+v", r.GetFromAddress())
	}
	if len(r.GetToAddresses()) != 1 || r.GetToAddresses()[0].GetIP() != "10.0.0.2" {
		t.Errorf("ToAddresses mismatch: %+v", r.GetToAddresses())
	}
	if len(r.GetFromIPBlock()) != 1 || r.GetFromIPBlock()[0].GetCIDR() != "10.0.1.0/24" {
		t.Errorf("FromIPBlock mismatch: %+v", r.GetFromIPBlock())
	}
	if len(r.GetToIPBlock()) != 1 || r.GetToIPBlock()[0].GetCIDR() != "10.0.2.0/24" {
		t.Errorf("ToIPBlock mismatch: %+v", r.GetToIPBlock())
	}
	if r.GetHttp().GetHost() != "svc" {
		t.Errorf("Http mismatch: %+v", r.GetHttp())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_ruleGroupToPayload -v`
Expected: FAIL — `ruleGroupToPayload` undefined.

- [ ] **Step 3: Implement**

```go
package microseg

import (
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

// ruleGroupToPayload converts an in-memory NetworkPolicyRuleGroup (computed by
// generateRules/caculatePolicyNodeRules*, unchanged by this migration) into
// the gRPC wire payload pushed to daemon.
func ruleGroupToPayload(rg *crdv1alpha1.NetworkPolicyRuleGroup) *pb.NetworkPolicyRuleGroupPayload {
	payload := &pb.NetworkPolicyRuleGroupPayload{
		Name:     rg.Name,
		Policy:   rg.Spec.Policy,
		NodeName: rg.Spec.NodeName,
	}
	for _, r := range rg.Spec.Rules {
		payload.Rules = append(payload.Rules, nodeRuleToPayload(r))
	}
	return payload
}

func nodeRuleToPayload(r crdv1alpha1.NodeRule) *pb.MicrosegNodeRule {
	out := &pb.MicrosegNodeRule{
		Name:      r.Name,
		Priority:  int32(r.Priority),
		Protocol:  r.Protocol,
		Direction: r.Direction,
		Action:    r.Action,
	}
	for _, p := range r.Ports {
		port := &pb.MicrosegPort{}
		if p.Protocol != nil {
			port.Protocol = string(*p.Protocol)
		}
		if p.Port != nil {
			port.Port = p.Port.String()
		}
		if p.EndPort != nil {
			port.EndPort = *p.EndPort
		}
		out.Ports = append(out.Ports, port)
	}
	for _, a := range r.ToAddresses {
		out.ToAddresses = append(out.ToAddresses, addressToPayload(a))
	}
	for _, b := range r.ToIPBlock {
		out.ToIPBlock = append(out.ToIPBlock, &pb.MicrosegIPBlock{CIDR: b.CIDR})
	}
	for _, a := range r.FromAddress {
		out.FromAddress = append(out.FromAddress, addressToPayload(a))
	}
	for _, b := range r.FromIPBlock {
		out.FromIPBlock = append(out.FromIPBlock, &pb.MicrosegIPBlock{CIDR: b.CIDR})
	}
	if r.Http != nil {
		out.Http = &pb.MicrosegHttp{Method: r.Http.Method, Path: r.Http.Path, Host: r.Http.Host}
	}
	return out
}

func addressToPayload(a crdv1alpha1.Address) *pb.MicrosegAddress {
	out := &pb.MicrosegAddress{IP: a.IP}
	if a.PodReference != nil {
		out.PodNamespace = a.PodReference.Namespace
		out.PodName = a.PodReference.Name
	}
	return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_ruleGroupToPayload -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/clustermanager/pkg/microseg/rulegroup_payload.go cmd/clustermanager/pkg/microseg/rulegroup_payload_test.go
git commit -m "feat(clustermanager/microseg): add CRD-to-gRPC-payload adapter"
```

---

## Task 9: Clustermanager — pushed-state cache + `ruleGroupPusher` (k8s and gRPC implementations)

**Files:**
- Create: `cmd/clustermanager/pkg/microseg/rulegroup_cache.go`
- Create: `cmd/clustermanager/pkg/microseg/rulegroup_pusher.go`
- Test: `cmd/clustermanager/pkg/microseg/rulegroup_cache_test.go`
- Test: `cmd/clustermanager/pkg/microseg/rulegroup_pusher_test.go`

**Interfaces:**
- Consumes: `ruleGroupToPayload` (Task 8), `MessageStreamClient.PushRuleGroup` (Task 3).
- Produces: `ruleGroupLister` interface (same shape as daemon's, Task 5) + `*pushedRuleGroupCache` implementing it, plus `ListForNode(nodeName string) []*crdv1alpha1.NetworkPolicyRuleGroup`; `ruleGroupPusher` interface (`Create`, `Update(cur, desired)`, `Delete(name)`, `DeleteByPolicy(policyName)`) with `*k8sRuleGroupPusher` and `*grpcRuleGroupPusher` implementations. Task 10 wires both into `NetworkPolicyController`.

- [ ] **Step 1: Write the failing cache test**

```go
package microseg

import (
	"testing"

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_pushedRuleGroupCache -v`
Expected: FAIL — `newPushedRuleGroupCache` undefined.

- [ ] **Step 3: Implement the cache**

```go
package microseg

import (
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

// ruleGroupLister is the subset of the generated NetworkPolicyRuleGroupLister
// that syncPolicyRules/deleteRuleGroup depend on. A *pushedRuleGroupCache
// implements it too, so that code (unchanged by this migration) works against
// either transport.
type ruleGroupLister interface {
	List(selector labels.Selector) ([]*crdv1alpha1.NetworkPolicyRuleGroup, error)
	Get(name string) (*crdv1alpha1.NetworkPolicyRuleGroup, error)
}

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

func (c *pushedRuleGroupCache) Set(rg *crdv1alpha1.NetworkPolicyRuleGroup) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byName[rg.Name] = rg
}

func (c *pushedRuleGroupCache) Delete(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byName, name)
}

func (c *pushedRuleGroupCache) Get(name string) (*crdv1alpha1.NetworkPolicyRuleGroup, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rg, ok := c.byName[name]
	if !ok {
		return nil, apierrors.NewNotFound(crdv1alpha1.Resource("networkpolicyrulegroup"), name)
	}
	return rg, nil
}

func (c *pushedRuleGroupCache) List(selector labels.Selector) ([]*crdv1alpha1.NetworkPolicyRuleGroup, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*crdv1alpha1.NetworkPolicyRuleGroup
	for _, rg := range c.byName {
		if selector == nil || selector.Matches(labels.Set(rg.Labels)) {
			out = append(out, rg)
		}
	}
	return out, nil
}

// ListForNode returns every rule group currently pushed for a given node,
// used to build the bootstrap snapshot when a daemon (re)connects (Task 10).
func (c *pushedRuleGroupCache) ListForNode(nodeName string) []*crdv1alpha1.NetworkPolicyRuleGroup {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*crdv1alpha1.NetworkPolicyRuleGroup
	for _, rg := range c.byName {
		if rg.Spec.NodeName == nodeName {
			out = append(out, rg)
		}
	}
	return out
}
```

- [ ] **Step 4: Run cache test to verify it passes**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_pushedRuleGroupCache -v`
Expected: PASS

- [ ] **Step 5: Write the failing pusher test**

```go
package microseg

import (
	"context"
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
}

func (f *fakeRuleGroupStream) PushRuleGroup(_ context.Context, nodeKey string, msgType pb.MessageType, req *pb.NetworkPolicyRuleGroupReq) error {
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
```

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_grpcRuleGroupPusher -v`
Expected: FAIL — `grpcRuleGroupPusher` undefined.

- [ ] **Step 7: Implement the pusher interface and both implementations**

```go
package microseg

import (
	"context"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/clientset/versioned"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

// ruleGroupPusher delivers rule-group changes to daemons; syncPolicyRules and
// deleteRuleGroup call it instead of the k8s clientset directly, so the same
// diff/control-flow logic works over either transport.
type ruleGroupPusher interface {
	Create(ctx context.Context, rg *crdv1alpha1.NetworkPolicyRuleGroup) error
	Update(ctx context.Context, cur, desired *crdv1alpha1.NetworkPolicyRuleGroup) error
	Delete(ctx context.Context, name string) error
	DeleteByPolicy(ctx context.Context, policyName string) error
}

// k8sRuleGroupPusher is today's behavior: write the CRD to the k8s apiserver.
// Used when MICROSEG_GRPC_ENABLED is unset.
type k8sRuleGroupPusher struct {
	clientset *versioned.Clientset
}

func (p *k8sRuleGroupPusher) Create(ctx context.Context, rg *crdv1alpha1.NetworkPolicyRuleGroup) error {
	_, err := p.clientset.MicrosegmentationV1alpha1().NetworkPolicyRuleGroups().Create(ctx, rg, v1.CreateOptions{})
	return err
}

func (p *k8sRuleGroupPusher) Update(ctx context.Context, cur, desired *crdv1alpha1.NetworkPolicyRuleGroup) error {
	newRule := cur.DeepCopy()
	newRule.Spec = desired.Spec
	_, err := p.clientset.MicrosegmentationV1alpha1().NetworkPolicyRuleGroups().Update(ctx, newRule, v1.UpdateOptions{})
	return err
}

func (p *k8sRuleGroupPusher) Delete(ctx context.Context, name string) error {
	return p.clientset.MicrosegmentationV1alpha1().NetworkPolicyRuleGroups().Delete(ctx, name, v1.DeleteOptions{})
}

func (p *k8sRuleGroupPusher) DeleteByPolicy(ctx context.Context, policyName string) error {
	err := p.clientset.MicrosegmentationV1alpha1().NetworkPolicyRuleGroups().DeleteCollection(ctx, v1.DeleteOptions{}, v1.ListOptions{
		LabelSelector: "kubernetes.io/networkpolicy-name=" + policyName,
	})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	return nil
}

// ruleGroupStreamPusher is the subset of rpcstream.MessageStreamClient this
// package needs — kept narrow so tests can fake it without a real stream.
type ruleGroupStreamPusher interface {
	PushRuleGroup(ctx context.Context, nodeKey string, msgType pb.MessageType, req *pb.NetworkPolicyRuleGroupReq) error
}

// grpcRuleGroupPusher pushes rule-group changes over the daemon<->clustermanager
// gRPC stream and keeps pushedRuleGroupCache in sync so RegisterOnConnect (Task
// 10) can serve bootstrap snapshots. Used when MICROSEG_GRPC_ENABLED=true.
type grpcRuleGroupPusher struct {
	cache  *pushedRuleGroupCache
	stream ruleGroupStreamPusher
}

func (p *grpcRuleGroupPusher) Create(ctx context.Context, rg *crdv1alpha1.NetworkPolicyRuleGroup) error {
	p.cache.Set(rg)
	return p.stream.PushRuleGroup(ctx, rg.Spec.NodeName+"-daemon", pb.MessageType_CREATE, &pb.NetworkPolicyRuleGroupReq{RuleGroup: ruleGroupToPayload(rg)})
}

func (p *grpcRuleGroupPusher) Update(ctx context.Context, _, desired *crdv1alpha1.NetworkPolicyRuleGroup) error {
	p.cache.Set(desired)
	return p.stream.PushRuleGroup(ctx, desired.Spec.NodeName+"-daemon", pb.MessageType_UPDATE, &pb.NetworkPolicyRuleGroupReq{RuleGroup: ruleGroupToPayload(desired)})
}

func (p *grpcRuleGroupPusher) Delete(ctx context.Context, name string) error {
	rg, err := p.cache.Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if err := p.stream.PushRuleGroup(ctx, rg.Spec.NodeName+"-daemon", pb.MessageType_DELETE, &pb.NetworkPolicyRuleGroupReq{RuleGroup: &pb.NetworkPolicyRuleGroupPayload{Name: name}}); err != nil {
		return err
	}
	p.cache.Delete(name)
	return nil
}

func (p *grpcRuleGroupPusher) DeleteByPolicy(ctx context.Context, policyName string) error {
	groups, err := p.cache.List(labels.SelectorFromValidatedSet(map[string]string{"kubernetes.io/networkpolicy-name": policyName}))
	if err != nil {
		return err
	}
	for _, rg := range groups {
		if err := p.Delete(ctx, rg.Name); err != nil {
			return err
		}
	}
	return nil
}
```

- [ ] **Step 8: Run test to verify it passes**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_grpcRuleGroupPusher -v`
Expected: PASS

- [ ] **Step 9: Check for regressions (scoped — do not run the bare package)**

**Do not run a bare `go test ./cmd/clustermanager/pkg/microseg/...`.** This package has several
pre-existing, unrelated failures at this plan's baseline — `TestNetworkPolicyController_caculatePolicy`,
`TestNetworkPolicyController_caculateAddressMap`, `TestNetworkPolicyController_caculateNodeRules`,
`TestPolicyIndex` (fragile pointer-comparison assertions), `TestCreateCRD` (needs a local envtest
apiserver not available here), and `Test_getServicePort` (a pre-existing nil-pointer panic that
**crashes the whole test binary**, potentially preventing tests after it from running/reporting in
the same invocation). None of this is caused by this task — out of scope to fix.

Instead run:
```
go test ./cmd/clustermanager/pkg/microseg/... -run 'Test_pushedRuleGroupCache|Test_grpcRuleGroupPusher'
go build ./cmd/clustermanager/pkg/microseg/...
```
Expected: the `-run` invocation PASSes; the build succeeds. This task adds new files only (no
existing code touched yet), so there is nothing else in this package for it to regress.

- [ ] **Step 10: Commit**

```bash
git add cmd/clustermanager/pkg/microseg/rulegroup_cache.go cmd/clustermanager/pkg/microseg/rulegroup_pusher.go cmd/clustermanager/pkg/microseg/rulegroup_cache_test.go cmd/clustermanager/pkg/microseg/rulegroup_pusher_test.go
git commit -m "feat(clustermanager/microseg): add pushed-state cache and rule group pusher"
```

---

## Task 10: Clustermanager — wire the pusher into `NetworkPolicyController` + bootstrap-on-connect

**Files:**
- Modify: `cmd/clustermanager/pkg/microseg/networkpolicy_controller.go`
- Test: `cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go` (add cases)

**Interfaces:**
- Consumes: `ruleGroupLister`/`ruleGroupPusher`/`*pushedRuleGroupCache` (Task 9), `ruleGroupToPayload` (Task 8), `rpcstream.MessageStream.OnConnect`/`.PushRuleGroupSync` (Tasks 2, 3).
- Produces: `NewNetworkPolicyController(..., stream rpcstream.MessageStream) *NetworkPolicyController` (signature change — `stream` may be `nil`), `(*NetworkPolicyController).RegisterOnConnect(stream rpcstream.MessageStream)`. Task 11 updates the one call site in `cmd/clustermanager/cmd/server.go`.

- [ ] **Step 1: Change the struct and constructor**

In `cmd/clustermanager/pkg/microseg/networkpolicy_controller.go`:

1. Change the `ruleGroupLister` field's type and add two fields to the `NetworkPolicyController` struct:

```go
	ruleGroupLister ruleGroupLister
```
```go
	pushedCache     *pushedRuleGroupCache
	ruleGroupPusher ruleGroupPusher
```

2. Change `NewNetworkPolicyController`'s signature to accept a stream, and branch the rule-group-specific setup:

```go
func NewNetworkPolicyController(clientset *versioned.Clientset, factory informers.SharedInformerFactory, crdFactory externalversions.SharedInformerFactory, writer mq.Writer, topic string, stream rpcstream.MessageStream) *NetworkPolicyController {
	policyInfomer := crdFactory.Microsegmentation().V1alpha1().ClusterNetworkPolicies().Informer()
	controller := NetworkPolicyController{
		clietset:             clientset,
		policyInfomer:        policyInfomer,
		clusterGroupInformer: crdFactory.Microsegmentation().V1alpha1().ClusterWorkloadSets().Informer(),
		podInformer:          factory.Core().V1().Pods().Informer(),
		namespaceInformer:    factory.Core().V1().Namespaces().Informer(),
		serviceInformer:      factory.Core().V1().Services().Informer(),
		nodeInformer:         factory.Core().V1().Nodes().Informer(),
		serviceLister:        factory.Core().V1().Services().Lister(),
		nodeLister:           factory.Core().V1().Nodes().Lister(),
		policyLister:         crdFactory.Microsegmentation().V1alpha1().ClusterNetworkPolicies().Lister(),
		clusterGroupLister:   crdFactory.Microsegmentation().V1alpha1().ClusterWorkloadSets().Lister(),
		podLister:            factory.Core().V1().Pods().Lister(),
		namespaceLister:      factory.Core().V1().Namespaces().Lister(),
		podSynced:            factory.Core().V1().Pods().Informer().HasSynced,
		namepaceSynced:       factory.Core().V1().Namespaces().Informer().HasSynced,
		nodeSynced:           factory.Core().V1().Nodes().Informer().HasSynced,
		clusterPolicySynced:  crdFactory.Microsegmentation().V1alpha1().ClusterNetworkPolicies().Informer().HasSynced,
		clusterGroupSynced:   crdFactory.Microsegmentation().V1alpha1().ClusterWorkloadSets().Informer().HasSynced,
		queue:                workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "networkpolicy-queue"),
		nodeQueue:            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "node_queue"),
		pod2Policy:           make(map[string]string, 100),
		NodesIpAddr:          make(map[string]struct{}, 100),
		mqWriter:             writer,
		mqTopic:              topic,
		firstSynced:          make(map[string]bool),
		ruleGroupMap:         make(map[string]sets.String),
	}

	if stream != nil {
		pushed := newPushedRuleGroupCache()
		controller.pushedCache = pushed
		controller.ruleGroupLister = pushed
		controller.ruleGroupSynced = func() bool { return true }
		controller.ruleGroupPusher = &grpcRuleGroupPusher{cache: pushed, stream: stream}
		controller.RegisterOnConnect(stream)
	} else {
		controller.ruleGroupLister = crdFactory.Microsegmentation().V1alpha1().NetworkPolicyRuleGroups().Lister()
		controller.ruleGroupSynced = crdFactory.Microsegmentation().V1alpha1().NetworkPolicyRuleGroups().Informer().HasSynced
		controller.ruleGroupPusher = &k8sRuleGroupPusher{clientset: clientset}
	}

	policyInfomer.AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.addClusterPolicy,
		UpdateFunc: controller.updateClusterPolicy,
		DeleteFunc: controller.deleteClusterPolicy,
	}, time.Hour*8)

	ver, err := clientset.DiscoveryClient.ServerVersion()
	if err != nil {
		logging.Get().Err(err).Msg("faild to get kubenetes version")
		return nil
	}
	v := k8s.GetKubeMininorVersion(ver.String())
	if v < 21 {
		controller.endpointsliceListerv1beta1 = factory.Discovery().V1beta1().EndpointSlices().Lister()
	} else {
		controller.endpointsliceLister = factory.Discovery().V1().EndpointSlices().Lister()
	}

	policyInfomer.AddIndexers(cache.Indexers{"pod-label-index": podLabelIndexFunc})

	err = controller.listNode()
	if err != nil {
		logging.Get().Err(err).Msgf("list node ip address failed")
		return nil
	}

	controller.clusterGroupInformer.AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.addClusterGroup,
		UpdateFunc: controller.updateClusterGroup,
		DeleteFunc: controller.deleteClusterGroup,
	}, time.Hour*8)

	controller.podInformer.AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.addPod,
		UpdateFunc: controller.updatePod,
		DeleteFunc: controller.deletePod,
	}, time.Hour*8)

	controller.namespaceInformer.AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.addNamespace,
		UpdateFunc: controller.updateNamespace,
		DeleteFunc: controller.deleteNamespace,
	}, time.Hour*8)

	controller.serviceInformer.AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.addService,
		UpdateFunc: controller.updateService,
		DeleteFunc: controller.deleteService,
	}, time.Hour*8)

	controller.nodeInformer.AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.addNode,
		UpdateFunc: controller.updateNode,
		DeleteFunc: controller.deleteNode,
	}, time.Hour*8)

	logging.Get().Info().Msg("create NetworkPolicyController")
	return &controller
}
```

(Everything from `policyInfomer.AddEventHandlerWithResyncPeriod` onward is copied unchanged from today's constructor — only the block replacing the single `ruleGroupLister`/`ruleGroupSynced` struct-literal fields with the `if stream != nil { ... } else { ... }` branch, inserted right after the struct literal, is new.)

Add `rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"` to the file's imports.

3. Add `RegisterOnConnect`, right after `NewNetworkPolicyController`:

```go
// RegisterOnConnect wires this controller's pushed-rule-group cache to the
// stream's OnConnect hook, so a (re)connecting daemon receives a full
// bootstrap snapshot of the rule groups clustermanager has already computed
// for its node — the gRPC-push equivalent of the initial List a k8s informer
// gets for free. No-op for node keys that aren't a daemon connection (e.g.
// "-monitor", which shares the same in-cluster stream).
func (npc *NetworkPolicyController) RegisterOnConnect(stream rpcstream.MessageStream) {
	stream.OnConnect(func(nodeKey string) {
		const suffix = "-daemon"
		if !strings.HasSuffix(nodeKey, suffix) || npc.pushedCache == nil {
			return
		}
		nodeName := strings.TrimSuffix(nodeKey, suffix)
		groups := npc.pushedCache.ListForNode(nodeName)
		if len(groups) == 0 {
			return
		}
		req := &pb.NetworkPolicyRuleGroupSyncReq{}
		for _, rg := range groups {
			req.RuleGroups = append(req.RuleGroups, ruleGroupToPayload(rg))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := stream.PushRuleGroupSync(ctx, nodeKey, req); err != nil {
			logging.Get().Err(err).Str("nodeKey", nodeKey).Msg("push rule group bootstrap snapshot")
		}
	})
}
```

Add `"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"` to the file's imports if not already present (it likely is not — `networkpolicy_controller.go` today has no gRPC/proto dependency).

- [ ] **Step 2: Replace the four CRD CRUD call sites in `syncPolicyRules`/`deleteRuleGroup`**

In `syncPolicyRules` (around line 1147):

```go
	for name := range deletingRuleGroups {
		err := npc.ruleGroupPusher.Delete(context.Background(), name)
		if err != nil {
			logging.Get().Error().Err(err).Msgf("delete rule group %s", name)
		}
	}
```

Around line 1153-1174 (Create/Update branch):

```go
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
```

In `deleteRuleGroup` (line 1391-1399):

```go
func (npc *NetworkPolicyController) deleteRuleGroup(policyName string) error {
	return npc.ruleGroupPusher.DeleteByPolicy(context.Background(), policyName)
}
```

- [ ] **Step 3: Write a test confirming the pusher is exercised (not the k8s clientset) when a stream is supplied**

Add to `cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go` (check the existing file's test setup helper — e.g. a `newTestController(t)`-style function — and construct the controller the same way that helper does, then override `ruleGroupPusher`/`ruleGroupLister` directly, since those are now plain struct fields settable from within the same package):

```go
func Test_syncPolicyRules_UsesInjectedPusher(t *testing.T) {
	npc := &NetworkPolicyController{
		ruleGroupLister: newPushedRuleGroupCache(),
		ruleGroupPusher: &grpcRuleGroupPusher{cache: newPushedRuleGroupCache(), stream: &fakeRuleGroupStream{}},
	}

	rules := map[string]*crdv1alpha1.NetworkPolicyRuleGroup{
		"node1": {
			ObjectMeta: v1.ObjectMeta{Name: "policy-node1", Labels: map[string]string{"kubernetes.io/networkpolicy-name": "policy"}},
			Spec:       crdv1alpha1.NetworkPolicyRuleGroupSpec{Policy: "policy", NodeName: "node1"},
		},
	}

	if err := npc.syncPolicyRules("policy", rules); err != nil {
		t.Fatalf("syncPolicyRules: %v", err)
	}

	pusher := npc.ruleGroupPusher.(*grpcRuleGroupPusher)
	stream := pusher.stream.(*fakeRuleGroupStream)
	if len(stream.pushed) != 1 || stream.pushed[0].msgType != pb.MessageType_CREATE {
		t.Fatalf("pushed = %+v, want one CREATE", stream.pushed)
	}
}
```

Adjust field names/imports to match whatever the existing test file already imports as `crdv1alpha1`/`v1`/`pb` — check the top of `networkpolicy_controller_test.go` before adding this test and reuse its existing import aliases rather than introducing new ones. If the existing tests construct `NetworkPolicyController` via a helper that doesn't set `ruleGroupLister`/`ruleGroupPusher`, this test must set them explicitly as shown (both are plain fields, same package, directly settable) since `syncPolicyRules` calls `npc.ruleGroupLister.List(...)` before reaching the pusher calls under test — with an empty `pushedRuleGroupCache`, `List` returns no current rule groups, which correctly drives the Create-not-Update branch this test wants to exercise.

- [ ] **Step 4: Run test to verify it fails, then passes**

Run: `go test ./cmd/clustermanager/pkg/microseg/... -run Test_syncPolicyRules_UsesInjectedPusher -v`
Expected first: FAIL (field/type mismatches before Steps 1-2 land). After Steps 1-2: PASS.

- [ ] **Step 5: Check for regressions (scoped — do not run the bare package)**

**Do not run a bare `go test ./cmd/clustermanager/pkg/microseg/...`.** This package has
pre-existing, unrelated failures at this plan's baseline (see Task 9's Step 9 for the full list),
including a nil-pointer panic in `Test_getServicePort` that crashes the whole test binary and can
prevent tests after it from running/reporting in the same invocation.

This step's real goal is narrower: catch any existing test that constructs `NetworkPolicyController`
via `NewNetworkPolicyController(...)` directly, whose call site needs a trailing `nil` argument
added for the new `stream` parameter (flag-off behavior, unchanged CRD path) — a signature-change
break, not a runtime failure. Compiling the test binary without running anything catches this
safely, without touching the panicking test:
```
go test -run '^$' -count=1 ./cmd/clustermanager/pkg/microseg/...
go test ./cmd/clustermanager/pkg/microseg/... -run Test_syncPolicyRules_UsesInjectedPusher -v
```
Expected: the first command reports `ok` (compiles cleanly, zero tests matched/run — confirms no
`NewNetworkPolicyController(...)` call site was left broken by the signature change); the second
PASSes (already covered in Step 4, re-confirm here in the context of the full file compiling).

- [ ] **Step 6: Commit**

```bash
git add cmd/clustermanager/pkg/microseg/networkpolicy_controller.go cmd/clustermanager/pkg/microseg/networkpolicy_controller_test.go
git commit -m "feat(clustermanager/microseg): wire rule group pusher and bootstrap-on-connect"
```

---

## Task 11: Clustermanager — wire `MICROSEG_GRPC_ENABLED` in `server.go`

**Files:**
- Modify: `cmd/clustermanager/cmd/server.go`

**Interfaces:**
- Consumes: `microseg.NewNetworkPolicyController(..., stream rpcstream.MessageStream)` (Task 10's new signature).

This task is wiring-only; verify with `go build` and the manual steps below.

- [ ] **Step 1: Update the one call site**

In `cmd/clustermanager/cmd/server.go`, line 162:

```go
	go microseg.NewNetworkPolicyController(agent.GetHostClient().TensorClientset, factory, tensorFactory, mqWriter, "ivan_microseg_status").Run(stopChan)
```

becomes:

```go
	var ruleGroupStream rpcstream.MessageStream
	if os.Getenv("MICROSEG_GRPC_ENABLED") == "true" {
		ruleGroupStream = inClusterStream
	}
	go microseg.NewNetworkPolicyController(agent.GetHostClient().TensorClientset, factory, tensorFactory, mqWriter, "ivan_microseg_status", ruleGroupStream).Run(stopChan)
```

`inClusterStream` is already in scope at this point in `NewServer()` (constructed at line 99: `inClusterStream := rpcstream.NewStreamFactory(rpcstream.WithPodNameKey()).Server("tcp", ":19090")`), and `os` is already imported. No new imports needed — `rpcstream` is already imported (used at line 99/102).

- [ ] **Step 2: Build**

Run: `go build ./cmd/clustermanager/...`
Expected: builds successfully.

- [ ] **Step 3: Commit**

```bash
git add cmd/clustermanager/cmd/server.go
git commit -m "feat(clustermanager): wire MICROSEG_GRPC_ENABLED rule group push path"
```

---

## Task 12: Full verification pass

**Files:** none (verification only).

- [ ] **Step 1: Build both binaries**

```bash
CGO_ENABLED=1 go build -o /tmp/daemon-build-check ./cmd/daemon
go build -o /tmp/clustermanager-build-check ./cmd/clustermanager
```

Expected: both succeed.

- [ ] **Step 2: Run the full test suite for every package touched**

Two of these packages have pre-existing, unrelated failures confirmed present at this plan's
baseline commit (before Task 1): `pkg/streaming`'s `Test_channel` hangs forever (`select {}`,
~10 min timeout then FAIL), and `cmd/clustermanager/pkg/microseg` has several pre-existing
failures including a nil-pointer panic in `Test_getServicePort` that crashes the whole test
binary (`TestNetworkPolicyController_caculatePolicy`, `TestNetworkPolicyController_caculateAddressMap`,
`TestNetworkPolicyController_caculateNodeRules`, `TestPolicyIndex`, `TestCreateCRD` also
pre-exist as failures/needs-envtest). None of this is caused by this plan — out of scope to fix.
Do not run a bare `go test` across those two package trees.

```bash
go test ./pkg/streaming/... -run 'Test_OnConnect_FiresWithConnectingNodeKey|Test_messageStream_Request|Test_messageStream_PushRuleGroup'
go test ./cmd/daemon/pkg/microseg/...
go test ./cmd/clustermanager/pkg/microseg/... -run 'Test_ruleGroupToPayload|Test_pushedRuleGroupCache|Test_grpcRuleGroupPusher|Test_syncPolicyRules_UsesInjectedPusher'
go test ./cmd/clustermanager/cmd/...
go test -run '^$' -count=1 ./pkg/streaming/... ./cmd/clustermanager/pkg/microseg/...
```

Expected: every `-run`-scoped invocation PASSes; `cmd/daemon/pkg/microseg` (no pre-existing
issues there — confirmed clean at baseline) PASSes in full; the final `-run '^$'` pair reports
`ok` for both packages with zero tests run, confirming everything in both trees still compiles
(catches any test-file compile break across either package without triggering the pre-existing
hang/panic).

- [ ] **Step 3: Run the broader repo test suite to catch any unnoticed breakage**

```bash
go test ./cmd/daemon/... ./cmd/clustermanager/... 2>&1 | grep -v "^ok" | tee /tmp/task12-broad-test.log
```

Expected: review `/tmp/task12-broad-test.log` for any FAIL entries beyond the known pre-existing
`cmd/clustermanager/pkg/microseg` list from Step 2 — anything new is this plan's responsibility to
fix; anything matching the known list is pre-existing and out of scope. This also re-runs the
pre-existing `heavy-agent`, `waf`, and other daemon-subpackage tests untouched by this plan,
confirming no accidental cross-package breakage there.

- [ ] **Step 4: Lint**

```bash
golangci-lint run ./cmd/daemon/... ./cmd/clustermanager/... ./pkg/streaming/...
```

Expected: no new findings. Fix anything this plan's new code introduces (e.g. `goimports` ordering with local-prefix `gitlab.com/piccolo_su/vegeta`, per root `CLAUDE.md`) before moving on — do not silence with `//nolint` unless a finding is a genuine false positive.

- [ ] **Step 5: Manual verification note (both flags must be set together)**

This plan does not include e2e/integration test infra (none exists for this path today — see spec's Testing section). Before flipping `MICROSEG_GRPC_ENABLED=true` on a real cluster: deploy clustermanager and daemon with the flag set on **both**, confirm via clustermanager logs that `RegisterOnConnect`'s snapshot push fires when a daemon pod starts, and confirm via daemon logs (`RuleGroupStreamHandler`/`RuleGroupSyncStreamHandler`) that rule groups are received and pushed to the local net-policy agent (`checkSync`'s periodic log line reports agreement, not `"heavy-agent lost policy"` or `"on daemon is in conflict with heavy-agent"` warnings — see `cmd/daemon/pkg/microseg/policyrule_controller.go`'s `checkSync`, unchanged by this plan).

- [ ] **Step 6: No commit for this task** (verification only — if Steps 1-4 surface fixes, make those fixes as part of whichever task's files they belong to, and amend that task's commit per normal workflow, not a new catch-all commit).

---

## Post-plan cleanup (explicitly out of scope for this plan)

Once `MICROSEG_GRPC_ENABLED=true` has been verified on a real cluster (per the spec's Rollout section), a follow-up plan should remove the flag and the dormant k8s-informer/CRD-write path (`NewRuleGroupController`, `k8sRuleGroupPusher`, the `else` branches added in Tasks 6, 7, 10, 11, and the `tensorFactory`/`externalversions` CRD-watch wiring in `cmd/daemon/main.go`). Do not do this cleanup as part of this plan — the Global Constraints require the old path to stay fully intact and byte-for-byte unchanged when the flag is off.
