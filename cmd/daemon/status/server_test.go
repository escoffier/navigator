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
