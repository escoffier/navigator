package rpcstream

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/anypb"

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

func (f *fakeSendMessageServer) Context() context.Context     { return context.Background() }
func (f *fakeSendMessageServer) SendMsg(m interface{}) error  { return nil }
func (f *fakeSendMessageServer) RecvMsg(m interface{}) error  { return nil }
func (f *fakeSendMessageServer) SetHeader(metadata.MD) error  { return nil }
func (f *fakeSendMessageServer) SendHeader(metadata.MD) error { return nil }
func (f *fakeSendMessageServer) SetTrailer(metadata.MD)       {}

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
