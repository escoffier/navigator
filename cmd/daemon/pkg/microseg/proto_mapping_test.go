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
