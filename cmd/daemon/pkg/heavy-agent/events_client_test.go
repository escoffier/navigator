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
