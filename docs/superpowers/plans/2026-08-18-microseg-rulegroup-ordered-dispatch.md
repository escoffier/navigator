# Ordered dispatch for microseg rule-group messages Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix [issue #3](https://github.com/escoffier/navigator/issues/3) — `pkg/streaming`'s
per-message dispatch (`go func(){ handler.OnX(...) }()` in `baseStream.Dispatch`) does not preserve
message ordering, so two rapid `UPDATE`s (or a `CREATE` racing the bootstrap `ReplaceAll` snapshot)
for the same microseg rule group can be applied out of order on the daemon, permanently, with no
self-healing.

**Architecture:** Add an opt-in "ordered" registration to `pkg/streaming`'s handler-dispatch path:
`AddOrderedHandler` (new, alongside the existing `AddHandler`) marks a message type for synchronous
(in receive-order) handler invocation instead of the default `go func(){...}()`. This is additive and
backward-compatible — every existing consumer of this framework (`HoneySpotReq`,
`NamespaceLabelSetReq`, `ImageSecReq`, `ComplianceScanReq`, `NodeLoadReq`, `ContainerMetricsReq`)
keeps calling plain `AddHandler` and is completely unaffected. Only the daemon's two microseg
rule-group handlers switch to `AddOrderedHandler`. Because `baseStream.Dispatch`'s receive loop is
already single-threaded per connection (one `Receiver()` call at a time), making handler invocation
synchronous for a given message type is sufficient to guarantee in-order application — no wire
protocol change, no new worker-pool abstraction, no `MessageHandler` interface change (this was
picked over the issue's other two listed fix directions — a per-key serializing worker pool, or a
monotonic generation field in the proto — because it requires the smallest, most contained diff for
an equivalent correctness guarantee; the issue explicitly lists all three as acceptable). This also
resolves the issue's second scenario (a `CREATE` racing the bootstrap `ReplaceAll`) for free, since
`RuleGroupSyncStreamHandler` (the bootstrap-snapshot handler) and `RuleGroupStreamHandler` (the
regular CRUD handler) both register as ordered on the same connection, so their handler bodies can
never run concurrently against each other either.

**Tech Stack:** Go, the existing `pkg/streaming` (`rpcstream`) gRPC stream framework.

**Spec:** `docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md` (see its
"Known limitations" section, second bullet) and
[github.com/escoffier/navigator issue #3](https://github.com/escoffier/navigator/issues/3).

## Global Constraints

- Zero behavior change for any handler that does not opt in via `AddOrderedHandler` — `AddHandler`'s
  existing async (`go func()`) dispatch must be provably unchanged (a regression test is required,
  not just an absence of a diff).
- Do not touch `s.processors`/`AddHandlerFunc`/`ProcessFunc` dispatch (the `processors` branch in
  `Dispatch`) — out of scope, unrelated to `MessageHandler`-based consumers.
- Only two call sites change behavior: `cmd/daemon/main.go`'s registration of
  `NetworkPolicyRuleGroupReq` and `NetworkPolicyRuleGroupSyncReq`. No other `AddHandler` call site in
  the repo (`HoneySpotReq`, `NamespaceLabelSetReq`, `ImageSecReq`, `ComplianceScanReq`, `NodeLoadReq`,
  `ContainerMetricsReq`) changes.
- Follow existing code style: `logging.Get()...` for logs, same locking pattern (`s.streamLock` in
  `streamfactory.go`, no new lock types), same map-initialization style as existing struct literals.
- `.golangci.yml`: `lll` (150 cols), `goimports` grouping, `cyclop` max-complexity 20.
- `cmd/daemon` builds with `CGO_ENABLED=1` (see `cmd/daemon/CLAUDE.md`) — the daemon-side task must
  verify with the documented build command, not a bare `go build`.

---

## Task 1: `AddOrderedHandler` on the low-level `Stream`/`baseStream`

**Files:**
- Modify: `pkg/streaming/stream.go`
- Test: `pkg/streaming/stream_test.go` (new file)

**Interfaces:**
- Produces: `Stream.AddOrderedHandler(msgName string, handler MessageHandler) error` (new interface
  method), implemented on `*baseStream`. `baseStream.ordered map[string]struct{}` (new field,
  initialized alongside the other maps in `NewServerStream`/`NewClientStream`). Consumed by Task 2's
  `messageStream.AddOrderedHandler` (calls `stream.AddOrderedHandler(name, handler)` on each
  per-connection `Stream`) and by Task 2's test fake.

- [ ] **Step 1: Write the failing tests**

Create `pkg/streaming/stream_test.go`:

```go
package rpcstream

import (
	"io"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

func Test_baseStream_Dispatch_OrderedHandlerPreservesOrder(t *testing.T) {
	payload1, err := anypb.New(&pb.NetworkPolicyRuleGroupReq{RuleGroup: &pb.NetworkPolicyRuleGroupPayload{Name: "first"}})
	if err != nil {
		t.Fatalf("anypb.New: %v", err)
	}
	payload2, err := anypb.New(&pb.NetworkPolicyRuleGroupReq{RuleGroup: &pb.NetworkPolicyRuleGroupPayload{Name: "second"}})
	if err != nil {
		t.Fatalf("anypb.New: %v", err)
	}
	msgs := []*pb.ClusterMessage{
		{ReqUUID: "1", MessageType: pb.MessageType_CREATE, Payload: payload1},
		{ReqUUID: "2", MessageType: pb.MessageType_CREATE, Payload: payload2},
	}

	var idx int
	recvExhausted := make(chan struct{})
	s := &baseStream{
		handlers: make(map[string]MessageHandler),
		ordered:  make(map[string]struct{}),
		sessions: make(map[string]*Session),
		stopChan: make(chan struct{}),
		Receiver: func() (*pb.ClusterMessage, error) {
			if idx < len(msgs) {
				m := msgs[idx]
				idx++
				return m, nil
			}
			<-recvExhausted
			return nil, io.EOF
		},
	}

	var mu sync.Mutex
	var order []string
	h := &MessageHandlerFuncs{
		CreateFunc: func(_ Stream, _ string, m protoreflect.ProtoMessage) {
			req := m.(*pb.NetworkPolicyRuleGroupReq)
			name := req.GetRuleGroup().GetName()
			if name == "first" {
				// If dispatch were still async, this sleep would let "second"
				// finish first. Under ordered dispatch it can't: Dispatch's
				// receive loop won't move on to receive/process "second"
				// until this call returns.
				time.Sleep(50 * time.Millisecond)
			}
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
		},
	}
	if err := s.AddOrderedHandler("NetworkPolicyRuleGroupReq", h); err != nil {
		t.Fatalf("AddOrderedHandler: %v", err)
	}

	go s.Dispatch()

	time.Sleep(200 * time.Millisecond)
	close(recvExhausted)

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Fatalf("order = %v, want [first second]", order)
	}
}

func Test_baseStream_Dispatch_UnorderedHandlerDoesNotBlockNextMessage(t *testing.T) {
	payload1, err := anypb.New(&pb.NetworkPolicyRuleGroupReq{RuleGroup: &pb.NetworkPolicyRuleGroupPayload{Name: "blocks-forever"}})
	if err != nil {
		t.Fatalf("anypb.New: %v", err)
	}
	payload2, err := anypb.New(&pb.NetworkPolicyRuleGroupReq{RuleGroup: &pb.NetworkPolicyRuleGroupPayload{Name: "should-still-run"}})
	if err != nil {
		t.Fatalf("anypb.New: %v", err)
	}
	msgs := []*pb.ClusterMessage{
		{ReqUUID: "1", MessageType: pb.MessageType_CREATE, Payload: payload1},
		{ReqUUID: "2", MessageType: pb.MessageType_CREATE, Payload: payload2},
	}

	var idx int
	recvExhausted := make(chan struct{})
	s := &baseStream{
		handlers: make(map[string]MessageHandler),
		sessions: make(map[string]*Session),
		stopChan: make(chan struct{}),
		Receiver: func() (*pb.ClusterMessage, error) {
			if idx < len(msgs) {
				m := msgs[idx]
				idx++
				return m, nil
			}
			<-recvExhausted
			return nil, io.EOF
		},
	}

	blockForever := make(chan struct{})
	secondCalled := make(chan string, 1)
	h := &MessageHandlerFuncs{
		CreateFunc: func(_ Stream, _ string, m protoreflect.ProtoMessage) {
			req := m.(*pb.NetworkPolicyRuleGroupReq)
			name := req.GetRuleGroup().GetName()
			if name == "blocks-forever" {
				<-blockForever
				return
			}
			secondCalled <- name
		},
	}
	// Plain AddHandler — NOT ordered. Existing async behavior must be unchanged.
	if err := s.AddHandler("NetworkPolicyRuleGroupReq", h); err != nil {
		t.Fatalf("AddHandler: %v", err)
	}

	go s.Dispatch()

	select {
	case name := <-secondCalled:
		if name != "should-still-run" {
			t.Fatalf("got %q, want should-still-run", name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second message's handler never ran — unordered handlers must not block the receive loop")
	}
	close(recvExhausted)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/streaming/... -run Test_baseStream_Dispatch -v`
Expected: FAIL — `s.AddOrderedHandler undefined` (compile error) for the first test; the second test
alone (using only pre-existing `AddHandler`) would currently pass, but leave it in the same new file
so the whole file fails to compile until Step 3 lands, which is expected RED for this task's new file.

- [ ] **Step 3: Add `ordered` state and `AddOrderedHandler`, branch `Dispatch`**

In `pkg/streaming/stream.go`, find the `Stream` interface:

```go
type Stream interface {
	Dispatch() error
	AddHandler(StreammsgName string, handler MessageHandler) error
	AddHandlerFunc(StreammsgName string, f ProcessFunc) error
	AddSession(id string, ack bool)
	DelSession(id string)
	DelAllSession()
	Send(*pb.ClusterMessage) error
	Response(ctx context.Context, reqUUID string) (protoreflect.ProtoMessage, error)
	SendResponse(reqUUID string, resp protoreflect.ProtoMessage) error
	Run(stopChan chan struct{})
	Dump() map[string]interface{}
	Clean()
}
```

Replace with:

```go
type Stream interface {
	Dispatch() error
	AddHandler(StreammsgName string, handler MessageHandler) error
	// AddOrderedHandler is like AddHandler, but Dispatch invokes this
	// handler synchronously (in receive order) instead of spawning a
	// goroutine per message. Use only for handlers whose relative message
	// order matters (see issue #3) — it introduces head-of-line blocking
	// for this message type on this connection.
	AddOrderedHandler(StreammsgName string, handler MessageHandler) error
	AddHandlerFunc(StreammsgName string, f ProcessFunc) error
	AddSession(id string, ack bool)
	DelSession(id string)
	DelAllSession()
	Send(*pb.ClusterMessage) error
	Response(ctx context.Context, reqUUID string) (protoreflect.ProtoMessage, error)
	SendResponse(reqUUID string, resp protoreflect.ProtoMessage) error
	Run(stopChan chan struct{})
	Dump() map[string]interface{}
	Clean()
}
```

Find the `baseStream` struct:

```go
type baseStream struct {
	stopChan    chan struct{}
	processors  map[string]ProcessFunc
	handlers    map[string]MessageHandler
	sessions    map[string]*Session
	queue       cache.Queue
	sessionLock sync.RWMutex
	Receiver    ReceiveFunc
	Sender      SenderFunc
}
```

Replace with:

```go
type baseStream struct {
	stopChan    chan struct{}
	processors  map[string]ProcessFunc
	handlers    map[string]MessageHandler
	// ordered holds the message names registered via AddOrderedHandler —
	// Dispatch invokes these synchronously instead of via go func() (see
	// issue #3). Empty/nil means "no ordering guarantee", the pre-existing
	// default for every handler registered via plain AddHandler.
	ordered     map[string]struct{}
	sessions    map[string]*Session
	queue       cache.Queue
	sessionLock sync.RWMutex
	Receiver    ReceiveFunc
	Sender      SenderFunc
}
```

Find `AddHandler`'s implementation:

```go
func (s *baseStream) AddHandler(msgName string, handler MessageHandler) error {
	logging.Get().Debug().Msgf("add handler for %s", msgName)
	s.handlers[msgName] = handler
	return nil
}
```

Add immediately after it:

```go
func (s *baseStream) AddOrderedHandler(msgName string, handler MessageHandler) error {
	logging.Get().Debug().Msgf("add ordered handler for %s", msgName)
	s.handlers[msgName] = handler
	s.ordered[msgName] = struct{}{}
	return nil
}

func (s *baseStream) isOrdered(msgName string) bool {
	_, ok := s.ordered[msgName]
	return ok
}
```

Find the handler-dispatch branch inside `Dispatch()`:

```go
		handler, ok := s.handlers[string(m.ProtoReflect().Descriptor().Name())]
		//	logging.Get().Info().Msgf("映射handler并处理 %v %v %v", in.MessageType, string(m.ProtoReflect().Descriptor().Name()), ok)
		if ok {
			logging.Get().Debug().Str("reqID", in.ReqUUID).Msg("handler dealing msg")
			go func() {
				switch in.MessageType {
				case pb.MessageType_CREATE:
					handler.OnCreate(s, in.ReqUUID, m)
				case pb.MessageType_READ:
					handler.OnRead(s, in.ReqUUID, m)
				case pb.MessageType_UPDATE:
					handler.OnUpdate(s, in.ReqUUID, m)
				case pb.MessageType_DELETE:
					handler.OnDelete(s, in.ReqUUID, m)
				}

			}()
			continue
		}
```

Replace with:

```go
		msgName := string(m.ProtoReflect().Descriptor().Name())
		handler, ok := s.handlers[msgName]
		//	logging.Get().Info().Msgf("映射handler并处理 %v %v %v", in.MessageType, string(m.ProtoReflect().Descriptor().Name()), ok)
		if ok {
			logging.Get().Debug().Str("reqID", in.ReqUUID).Msg("handler dealing msg")
			dispatch := func() {
				switch in.MessageType {
				case pb.MessageType_CREATE:
					handler.OnCreate(s, in.ReqUUID, m)
				case pb.MessageType_READ:
					handler.OnRead(s, in.ReqUUID, m)
				case pb.MessageType_UPDATE:
					handler.OnUpdate(s, in.ReqUUID, m)
				case pb.MessageType_DELETE:
					handler.OnDelete(s, in.ReqUUID, m)
				}
			}
			if s.isOrdered(msgName) {
				dispatch()
			} else {
				go dispatch()
			}
			continue
		}
```

Finally, find `NewServerStream` and `NewClientStream`. In each, the `baseStream: baseStream{...}` struct
literal currently reads:

```go
			baseStream: baseStream{
				stopChan:   make(chan struct{}),
				processors: make(map[string]ProcessFunc, 0),
				handlers:   make(map[string]MessageHandler, 0),
				sessions:   make(map[string]*Session),
```

(this exact block appears twice, once in `NewServerStream`, once in `NewClientStream`). In **both**
places, add an `ordered` line so the block reads:

```go
			baseStream: baseStream{
				stopChan:   make(chan struct{}),
				processors: make(map[string]ProcessFunc, 0),
				handlers:   make(map[string]MessageHandler, 0),
				ordered:    make(map[string]struct{}, 0),
				sessions:   make(map[string]*Session),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/streaming/... -run Test_baseStream_Dispatch -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add pkg/streaming/stream.go pkg/streaming/stream_test.go
git commit -m "feat(streaming): add AddOrderedHandler for synchronous, in-order message dispatch"
```

---

## Task 2: `AddOrderedHandler` on `MessageStream`/`messageStream`, propagated to connections

**Files:**
- Modify: `pkg/streaming/streamfactory.go`
- Modify: `pkg/streaming/rulegroup_client_test.go` (extend the existing `fakeStream` test double)
- Test: `pkg/streaming/orderedhandler_test.go` (new file)

**Interfaces:**
- Consumes: Task 1's `Stream.AddOrderedHandler(msgName string, handler MessageHandler) error`.
- Produces: `MessageStream.AddOrderedHandler(msg protoreflect.ProtoMessage, handler MessageHandler) error`
  (new interface method), implemented on `*messageStream`. Consumed by Task 3's daemon `main.go`
  call sites.

- [ ] **Step 1: Write the failing tests**

First, extend `fakeStream` in `pkg/streaming/rulegroup_client_test.go` so it keeps satisfying the
`Stream` interface (which Task 1 just extended) and so this task's test can observe what gets called.
Find:

```go
type fakeStream struct {
	sent []*pb.ClusterMessage
}

func (f *fakeStream) Dispatch() error                          { return nil }
func (f *fakeStream) AddHandler(string, MessageHandler) error  { return nil }
func (f *fakeStream) AddHandlerFunc(string, ProcessFunc) error { return nil }
```

Replace with:

```go
type fakeStream struct {
	sent        []*pb.ClusterMessage
	handlerAdds []string
	orderedAdds []string
}

func (f *fakeStream) Dispatch() error { return nil }
func (f *fakeStream) AddHandler(name string, _ MessageHandler) error {
	f.handlerAdds = append(f.handlerAdds, name)
	return nil
}
func (f *fakeStream) AddOrderedHandler(name string, _ MessageHandler) error {
	f.orderedAdds = append(f.orderedAdds, name)
	return nil
}
func (f *fakeStream) AddHandlerFunc(string, ProcessFunc) error { return nil }
```

Now create `pkg/streaming/orderedhandler_test.go`:

```go
package rpcstream

import (
	"testing"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

func Test_messageStream_AddOrderedHandler_PropagatesToExistingStreams(t *testing.T) {
	fs := &fakeStream{}
	s := &messageStream{
		streams:      map[string]Stream{"node1-daemon": fs},
		hanlders:     map[string]MessageHandler{},
		orderedNames: map[string]struct{}{},
	}

	h := &MessageHandlerFuncs{}
	if err := s.AddOrderedHandler(&pb.NetworkPolicyRuleGroupReq{}, h); err != nil {
		t.Fatalf("AddOrderedHandler: %v", err)
	}

	if len(fs.orderedAdds) != 1 || fs.orderedAdds[0] != "NetworkPolicyRuleGroupReq" {
		t.Fatalf("orderedAdds = %v, want [NetworkPolicyRuleGroupReq]", fs.orderedAdds)
	}
	if len(fs.handlerAdds) != 0 {
		t.Fatalf("handlerAdds = %v, want none (ordered registration must not also call plain AddHandler)", fs.handlerAdds)
	}
	if _, ok := s.orderedNames["NetworkPolicyRuleGroupReq"]; !ok {
		t.Fatal("orderedNames not recorded on messageStream")
	}
}

func Test_AddOrderedHandler_NewConnectionInheritsOrdering(t *testing.T) {
	f := &streamFactory{}
	srv := f.Server("tcp", ":0").(*messageStreamServer)

	h := &MessageHandlerFuncs{}
	if err := srv.AddOrderedHandler(&pb.NetworkPolicyRuleGroupReq{}, h); err != nil {
		t.Fatalf("AddOrderedHandler: %v", err)
	}

	connected := make(chan string, 1)
	srv.OnConnect(func(nodeKey string) { connected <- nodeKey })

	fake := newFakeSendMessageServer()
	go func() {
		_ = srv.SendMessage(&registerOnceStream{fakeSendMessageServer: fake, nodeKey: "node1-daemon"})
	}()

	select {
	case <-connected:
	case <-time.After(2 * time.Second):
		t.Fatal("stream never connected")
	}

	srv.streamLock.Lock()
	rs := srv.streams["node1-daemon"]
	srv.streamLock.Unlock()

	bs, ok := rs.(*serverStream)
	if !ok {
		t.Fatalf("stream is %T, want *serverStream", rs)
	}
	if _, ordered := bs.ordered["NetworkPolicyRuleGroupReq"]; !ordered {
		t.Fatal("newly-connected stream did not inherit the ordered registration")
	}

	close(fake.closed)
}
```

(`newFakeSendMessageServer` and `registerOnceStream` already exist in `pkg/streaming/onconnect_test.go`
— same package, no import needed.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/streaming/... -run 'Test_messageStream_AddOrderedHandler|Test_AddOrderedHandler' -v`
Expected: FAIL — `messageStream` has no field `orderedNames`, `*messageStream` has no method
`AddOrderedHandler` (compile errors).

- [ ] **Step 3: Add `AddOrderedHandler` to `MessageStream`/`messageStream`, wire the two propagation loops**

In `pkg/streaming/streamfactory.go`, find the `MessageStream` interface:

```go
type MessageStream interface {
	MessageStreamClient
	Start() error
	AddHandler(msg protoreflect.ProtoMessage, handler MessageHandler) error
	AddHandlerFunc(msg protoreflect.ProtoMessage, f ProcessFunc) error
	Response(stream Stream, reqUUID string, resp protoreflect.ProtoMessage) error
	DumpStreams() string
	OnConnect(f func(nodeKey string))
	ConnectedNodeKeys() []string
}
```

Replace with:

```go
type MessageStream interface {
	MessageStreamClient
	Start() error
	AddHandler(msg protoreflect.ProtoMessage, handler MessageHandler) error
	// AddOrderedHandler is like AddHandler, but messages of this type are
	// dispatched synchronously, in receive order, on every connection —
	// see Stream.AddOrderedHandler and issue #3.
	AddOrderedHandler(msg protoreflect.ProtoMessage, handler MessageHandler) error
	AddHandlerFunc(msg protoreflect.ProtoMessage, f ProcessFunc) error
	Response(stream Stream, reqUUID string, resp protoreflect.ProtoMessage) error
	DumpStreams() string
	OnConnect(f func(nodeKey string))
	ConnectedNodeKeys() []string
}
```

Find the `messageStream` struct:

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

Replace with:

```go
type messageStream struct {
	streams    map[string]Stream
	processors map[string]ProcessFunc
	hanlders   map[string]MessageHandler
	// orderedNames holds the message names registered via AddOrderedHandler
	// — every new connection registers these via Stream.AddOrderedHandler
	// instead of Stream.AddHandler (see issue #3). A name in hanlders but
	// not here got a plain AddHandler and dispatches unordered, as before.
	orderedNames map[string]struct{}
	KeyToLabel   map[string]string
	noderKey     string
	Label        string
	streamLock   sync.Mutex
	onConnect    func(nodeKey string)
}
```

Find `AddHandler`'s implementation on `*messageStream`:

```go
func (s *messageStream) AddHandler(msg protoreflect.ProtoMessage, handler MessageHandler) error {
	s.streamLock.Lock()
	defer s.streamLock.Unlock()

	messageName := string(msg.ProtoReflect().Descriptor().Name())
	logging.Get().Info().Msgf("add handler for : %s", messageName)
	s.hanlders[messageName] = handler
	for _, stream := range s.streams {
		stream.AddHandler(messageName, handler)
	}
	return nil

}
```

Add immediately after it:

```go
func (s *messageStream) AddOrderedHandler(msg protoreflect.ProtoMessage, handler MessageHandler) error {
	s.streamLock.Lock()
	defer s.streamLock.Unlock()

	messageName := string(msg.ProtoReflect().Descriptor().Name())
	logging.Get().Info().Msgf("add ordered handler for : %s", messageName)
	s.hanlders[messageName] = handler
	s.orderedNames[messageName] = struct{}{}
	for _, stream := range s.streams {
		stream.AddOrderedHandler(messageName, handler)
	}
	return nil
}
```

Find the two factory functions. `(f *streamFactory) Server(...)` currently builds:

```go
func (f *streamFactory) Server(network string, address string) MessageStream {
	return &messageStreamServer{
		network: network,
		address: address,
		messageStream: messageStream{
			streams:    make(map[string]Stream, 0),
			processors: make(map[string]ProcessFunc, 0),
			hanlders:   make(map[string]MessageHandler, 0),
			KeyToLabel: make(map[string]string, 0),
			noderKey:   f.NodeKey,
			Label:      f.Label,
		},
	}
}
```

Add an `orderedNames` line:

```go
func (f *streamFactory) Server(network string, address string) MessageStream {
	return &messageStreamServer{
		network: network,
		address: address,
		messageStream: messageStream{
			streams:      make(map[string]Stream, 0),
			processors:   make(map[string]ProcessFunc, 0),
			hanlders:     make(map[string]MessageHandler, 0),
			orderedNames: make(map[string]struct{}, 0),
			KeyToLabel:   make(map[string]string, 0),
			noderKey:     f.NodeKey,
			Label:        f.Label,
		},
	}
}
```

`(f *streamFactory) Client(...)` has the identical shape — apply the same `orderedNames` addition
there too:

```go
func (f *streamFactory) Client(remoteAddress string) MessageStream {
	logging.Get().Info().Str("remoteAddress", remoteAddress).Msg("Client")
	return &messageStreamClient{
		remoteAddress: remoteAddress,
		messageStream: messageStream{
			streams:      make(map[string]Stream, 0),
			processors:   make(map[string]ProcessFunc, 3),
			hanlders:     make(map[string]MessageHandler, 0),
			orderedNames: make(map[string]struct{}, 0),
			KeyToLabel:   make(map[string]string, 0),
			noderKey:     f.NodeKey,
			Label:        f.Label,
		},
		reConnect: false,
	}
}
```

Now the two propagation loops. In `(s *messageStreamServer) SendMessage(...)`, find:

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
```

Replace with:

```go
	s.streamLock.Lock()
	s.streams[in.NodeKey] = rs
	for name, fun := range s.processors {
		s.streams[in.NodeKey].AddHandlerFunc(name, fun)
	}
	for name, handler := range s.hanlders {
		if _, ordered := s.orderedNames[name]; ordered {
			s.streams[in.NodeKey].AddOrderedHandler(name, handler)
		} else {
			s.streams[in.NodeKey].AddHandler(name, handler)
		}
	}
	onConnect := s.onConnect
	s.streamLock.Unlock()
```

In `(c *messageStreamClient) Start()`, find:

```go
			// add handler
			c.streamLock.Lock()
			c.streams[defaultNodeKey] = cs
			for name, fun := range c.processors {
				_ = c.streams[defaultNodeKey].AddHandlerFunc(name, fun)
			}
			for name, handler := range c.hanlders {
				_ = c.streams[defaultNodeKey].AddHandler(name, handler)
			}
			c.streamLock.Unlock()
```

Replace with:

```go
			// add handler
			c.streamLock.Lock()
			c.streams[defaultNodeKey] = cs
			for name, fun := range c.processors {
				_ = c.streams[defaultNodeKey].AddHandlerFunc(name, fun)
			}
			for name, handler := range c.hanlders {
				if _, ordered := c.orderedNames[name]; ordered {
					_ = c.streams[defaultNodeKey].AddOrderedHandler(name, handler)
				} else {
					_ = c.streams[defaultNodeKey].AddHandler(name, handler)
				}
			}
			c.streamLock.Unlock()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/streaming/... -run 'Test_messageStream_AddOrderedHandler|Test_AddOrderedHandler' -v`
Expected: PASS.

Run the whole package (excluding the pre-existing, unrelated hanging `Test_channel` — scope with
`-run`) to catch fallout: `go test ./pkg/streaming/... -run 'Test_messageStream|Test_OnConnect|Test_AddOrderedHandler|Test_baseStream'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/streaming/streamfactory.go pkg/streaming/rulegroup_client_test.go pkg/streaming/orderedhandler_test.go
git commit -m "feat(streaming): propagate AddOrderedHandler across existing and future connections"
```

---

## Task 3: Switch the daemon's microseg rule-group handlers to ordered dispatch

**Files:**
- Modify: `cmd/daemon/main.go`

**Interfaces:**
- Consumes: Task 2's `MessageStream.AddOrderedHandler(msg protoreflect.ProtoMessage, handler MessageHandler) error`.

- [ ] **Step 1: Make the change**

In `cmd/daemon/main.go`, find:

```go
			_ = rpcStream.AddHandler(&streampb.NetworkPolicyRuleGroupReq{}, &microseg.RuleGroupStreamHandler{Controller: ruleController})
			_ = rpcStream.AddHandler(&streampb.NetworkPolicyRuleGroupSyncReq{}, &microseg.RuleGroupSyncStreamHandler{Controller: ruleController})
```

Replace with:

```go
			// Ordered, not plain AddHandler: these carry ordered state
			// replication (CREATE/UPDATE/DELETE for the same rule group,
			// plus the bootstrap snapshot), where pkg/streaming's default
			// per-message-goroutine dispatch does not preserve receive
			// order (issue #3). Both handlers share the same connection's
			// ordered set, so the bootstrap snapshot and a regular CRUD
			// event for the same rule group also can't race each other.
			_ = rpcStream.AddOrderedHandler(&streampb.NetworkPolicyRuleGroupReq{}, &microseg.RuleGroupStreamHandler{Controller: ruleController})
			_ = rpcStream.AddOrderedHandler(&streampb.NetworkPolicyRuleGroupSyncReq{}, &microseg.RuleGroupSyncStreamHandler{Controller: ruleController})
```

- [ ] **Step 2: Verify it builds**

`cmd/daemon` requires `CGO_ENABLED=1` (see `cmd/daemon/CLAUDE.md`). Run, from the repo root:

`CGO_ENABLED=1 go build -o /tmp/daemon-build-check cmd/daemon/main.go`

Expected: success (no output, exit 0). This is a CGO binary with native dependencies already
present in the dev environment per the project's existing build docs — if the build fails for
reasons unrelated to this change (missing native libs, environment-specific), fall back to
`go vet ./cmd/daemon/...` to confirm the package at least type-checks, and note the discrepancy in
your report; do not attempt to install missing native dependencies as part of this task.

- [ ] **Step 3: Commit**

```bash
git add cmd/daemon/main.go
git commit -m "fix(daemon/microseg): dispatch rule-group stream messages in order"
```

---

## Task 4: Document the fix in the migration spec

**Files:**
- Modify: `docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md`

**Interfaces:** None — documentation only.

- [ ] **Step 1: Update the "Known limitations" bullet for issue #3**

In `docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md`, find the second
bullet under "### Known limitations" (the current text reads, after the issue #2 fix already landed
and reworded the heading/intro):

```
- **`pkg/streaming`'s per-message dispatch (`go func(){ handler.OnX(...) }()` in `stream.go`) does
  not preserve message ordering** (tracked as
  [#3](https://github.com/escoffier/navigator/issues/3)), and this migration is the first user of
  that framework to put
  ordered state replication (CREATE/UPDATE/DELETE for the same rule group) on it — every prior use
  (compliance scans, node load queries) was idempotent one-shot RPCs where order didn't matter. Two
  `UPDATE`s for the same rule group in quick succession can be applied out of order, and there is no
  self-healing: `checkSync` only warns on divergence, it never re-syncs. Needs either synchronous
  per-rule-group-name dispatch, a serializing worker keyed by rule-group name, or a monotonic
  generation/resourceVersion carried in the payload so stale messages can be dropped on receipt.
```

Replace with:

```
- **`pkg/streaming`'s per-message dispatch (`go func(){ handler.OnX(...) }()` in `stream.go`) does
  not preserve message ordering** (tracked as
  [#3](https://github.com/escoffier/navigator/issues/3), fixed). This migration was the first user
  of that framework to put ordered state replication (CREATE/UPDATE/DELETE for the same rule group)
  on it — every prior use (compliance scans, node load queries) was idempotent one-shot RPCs where
  order didn't matter, so the framework never needed an ordering guarantee. Fixed by adding an
  opt-in `AddOrderedHandler` (`pkg/streaming/stream.go`, `streamfactory.go`): message types
  registered this way dispatch synchronously, in receive order, instead of via `go func()`; every
  other consumer of the framework is unaffected since it keeps using plain `AddHandler`. The
  daemon's two microseg rule-group handlers (`cmd/daemon/main.go`) are the only callers of
  `AddOrderedHandler` today.
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-08-18-microseg-rulegroup-grpc-migration-design.md
git commit -m "docs: mark issue #3 (unordered per-message dispatch) as fixed in migration spec"
```
