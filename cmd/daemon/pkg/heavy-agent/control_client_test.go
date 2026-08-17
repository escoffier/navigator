package heavyagent

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
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
