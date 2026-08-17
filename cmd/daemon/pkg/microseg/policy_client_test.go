package microseg

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"k8s.io/apimachinery/pkg/util/intstr"

	heavyagent "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

type fakeControlServer struct {
	pb.UnimplementedNetPolicyControlServer
	lastAddReq    *pb.AddPolicyRuleRequest
	lastDeleteReq *pb.DeletePolicyRuleRequest
	lastPodUpReq  *pb.PodUpRequest
	status        int32
}

func (f *fakeControlServer) AddPolicyRule(_ context.Context, req *pb.AddPolicyRuleRequest) (*pb.StatusResponse, error) {
	f.lastAddReq = req
	return &pb.StatusResponse{Status: f.status}, nil
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

func Test_policyClient_AddPolicy(t *testing.T) {
	srv := &fakeControlServer{}
	cli := newTestPolicyClient(t, srv)

	port := intstr.FromInt(8080)
	rule := &PolicyRule{
		PolicyName: "test-policy",
		Rules: []NodeRule{{
			Action:      "Allow",
			Direction:   "ingress",
			Protocol:    "TCP",
			FromAddress: []Address{{IP: "10.0.0.1"}},
			ToAddresses: []Address{{IP: "10.0.0.2"}},
			Ports:       []crdv1alpha1.NetworkPolicyPort{{Port: &port}},
		}},
	}

	if err := cli.AddPolicy(rule); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	if srv.lastAddReq.GetPolicyName() != "test-policy" {
		t.Errorf("server received policy_name = %q, want %q", srv.lastAddReq.GetPolicyName(), "test-policy")
	}
	if len(srv.lastAddReq.GetRules()) != 1 {
		t.Fatalf("server received %d rules, want 1", len(srv.lastAddReq.GetRules()))
	}
	spec := srv.lastAddReq.GetRules()[0]
	if spec.GetAction() != pb.PolicyAction_POLICY_ACTION_ALLOW {
		t.Errorf("action = %v, want ALLOW", spec.GetAction())
	}
	if spec.GetDirection() != pb.FlowDirection_FLOW_DIRECTION_INGRESS {
		t.Errorf("direction = %v, want INGRESS", spec.GetDirection())
	}
	if len(spec.GetFromAddresses()) != 1 || spec.GetFromAddresses()[0].GetIp() != "10.0.0.1" {
		t.Errorf("from_addresses = %+v, want one address with ip=10.0.0.1", spec.GetFromAddresses())
	}
	if len(spec.GetToAddresses()) != 1 || spec.GetToAddresses()[0].GetIp() != "10.0.0.2" {
		t.Errorf("to_addresses = %+v, want one address with ip=10.0.0.2", spec.GetToAddresses())
	}
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
