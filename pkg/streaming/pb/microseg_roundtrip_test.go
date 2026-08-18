package pb

import (
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestNetworkPolicyRuleGroupPayload_RoundTrip(t *testing.T) {
	protocol := "TCP"
	payload := &NetworkPolicyRuleGroupPayload{
		Name:     "policy-node1",
		Policy:   "policy",
		NodeName: "node1",
		Rules: []*MicrosegNodeRule{{
			Name:      "rule1",
			Priority:  100,
			Protocol:  "TCP",
			Direction: "ingress",
			Action:    "Allow",
			Ports:     []*MicrosegPort{{Protocol: protocol, Port: "80", EndPort: 0}},
			ToAddresses: []*MicrosegAddress{{IP: "10.0.0.2", PodNamespace: "ns", PodName: "pod"}},
			FromIPBlock: []*MicrosegIPBlock{{CIDR: "10.0.0.0/24"}},
			Http:        &MicrosegHttp{Method: "GET", Path: "/", Host: "example.com"},
		}},
	}

	data, err := proto.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := &NetworkPolicyRuleGroupPayload{}
	if err := proto.Unmarshal(data, got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.GetNodeName() != "node1" || len(got.GetRules()) != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.GetRules()[0].GetHttp().GetHost() != "example.com" {
		t.Fatalf("Http field lost in round-trip: %+v", got.GetRules()[0])
	}
}
