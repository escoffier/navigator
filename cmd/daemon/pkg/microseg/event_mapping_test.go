package microseg

import (
	"encoding/json"
	"testing"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
)

func TestEventPayloadFromPolicyMatch(t *testing.T) {
	evt := &pb.PolicyMatchEvent{
		Protocol:   pb.L4Protocol_L4_PROTOCOL_TCP,
		Action:     pb.PolicyAction_POLICY_ACTION_ALLOW,
		Direction:  pb.FlowDirection_FLOW_DIRECTION_EGRESS,
		SrcPort:    12345,
		DstPort:    443,
		SrcIp:      "10.0.0.1",
		DstIp:      "10.0.0.2",
		PolicyName: "test-policy",
	}

	payload := EventPayloadFromPolicyMatch(evt)
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded struct {
		Proto      int    `json:"proto"`
		Action     int    `json:"action"`
		Direction  int    `json:"direction"`
		SrcPort    int    `json:"src_port"`
		DstPort    int    `json:"dst_port"`
		SrcIP      string `json:"src_ip"`
		DstIP      string `json:"dst_ip"`
		PolicyName string `json:"policy_name"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Proto != 6 {
		t.Errorf("proto = %d, want 6 (TCP)", decoded.Proto)
	}
	if decoded.Action != 1 {
		t.Errorf("action = %d, want 1 (Allow)", decoded.Action)
	}
	if decoded.Direction != 1 {
		t.Errorf("direction = %d, want 1 (Egress)", decoded.Direction)
	}
	if decoded.SrcPort != 12345 || decoded.DstPort != 443 {
		t.Errorf("ports = %d/%d, want 12345/443", decoded.SrcPort, decoded.DstPort)
	}
	if decoded.SrcIP != "10.0.0.1" || decoded.DstIP != "10.0.0.2" {
		t.Errorf("ips = %s/%s, want 10.0.0.1/10.0.0.2", decoded.SrcIP, decoded.DstIP)
	}
	if decoded.PolicyName != "test-policy" {
		t.Errorf("policy_name = %q, want test-policy", decoded.PolicyName)
	}
}

func TestPolicyActionToWireCode(t *testing.T) {
	tests := []struct {
		in   pb.PolicyAction
		want int
	}{
		{pb.PolicyAction_POLICY_ACTION_DENY, 0},
		{pb.PolicyAction_POLICY_ACTION_ALLOW, 1},
		{pb.PolicyAction_POLICY_ACTION_ALERT, 2},
		{pb.PolicyAction_POLICY_ACTION_UNSPECIFIED, 0},
	}
	for _, tt := range tests {
		if got := policyActionToWireCode(tt.in); got != tt.want {
			t.Errorf("policyActionToWireCode(%v) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestL4ProtocolToWireCode(t *testing.T) {
	tests := []struct {
		in   pb.L4Protocol
		want int
	}{
		{pb.L4Protocol_L4_PROTOCOL_TCP, 6},
		{pb.L4Protocol_L4_PROTOCOL_UDP, 17},
		{pb.L4Protocol_L4_PROTOCOL_ICMP, 1},
		{pb.L4Protocol_L4_PROTOCOL_UNSPECIFIED, 0},
	}
	for _, tt := range tests {
		if got := l4ProtocolToWireCode(tt.in); got != tt.want {
			t.Errorf("l4ProtocolToWireCode(%v) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
