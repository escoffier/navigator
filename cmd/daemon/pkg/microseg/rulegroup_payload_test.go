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
			Name:        "rule1",
			Priority:    100,
			Protocol:    "TCP",
			Direction:   "ingress",
			Action:      "Allow",
			Ports:       []*pb.MicrosegPort{{Protocol: "TCP", Port: "80", EndPort: 90}},
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
