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
