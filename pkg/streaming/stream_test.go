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
