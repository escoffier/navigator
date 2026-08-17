package microseg

import "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"

// microsegEventPayload mirrors the fields gitlab.com/security-rd/go-pkg/model.TensorMicrosegEvent
// expects the daemon to populate (its embedded Base is filled in by clustermanager itself,
// see cmd/clustermanager/pkg/clusterserver/filter.go's FillResToMicroSegLog). The int codes
// for Proto/Action/Direction must match the legacy NET_POLICY_RULE/FLOW_DIR/IPPROTO_* values
// clustermanager's filter.go switches on -- NOT the new proto enums' own numbering.
type microsegEventPayload struct {
	Proto      int    `json:"proto"`
	Action     int    `json:"action"`
	Direction  int    `json:"direction"`
	SrcPort    int    `json:"src_port"`
	DstPort    int    `json:"dst_port"`
	SrcIP      string `json:"src_ip"`
	DstIP      string `json:"dst_ip"`
	PolicyName string `json:"policy_name"`
}

// policyActionToWireCode mirrors NET_POLICY_RULE (net-policy.h:74-82): Deny=0, Allow=1, Mark(Alert)=2.
func policyActionToWireCode(action pb.PolicyAction) int {
	switch action {
	case pb.PolicyAction_POLICY_ACTION_ALLOW:
		return 1
	case pb.PolicyAction_POLICY_ACTION_ALERT:
		return 2
	default:
		return 0
	}
}

// flowDirectionToWireCode mirrors FLOW_DIR (net-policy.h:85-89): Ingress=0, Egress=1.
func flowDirectionToWireCode(direction pb.FlowDirection) int {
	if direction == pb.FlowDirection_FLOW_DIRECTION_EGRESS {
		return 1
	}
	return 0
}

// l4ProtocolToWireCode mirrors the raw IPPROTO_* values NetProtoConvert produces
// (net-policy.cpp:60-71): ICMP=1, TCP=6, UDP=17.
func l4ProtocolToWireCode(protocol pb.L4Protocol) int {
	switch protocol {
	case pb.L4Protocol_L4_PROTOCOL_TCP:
		return 6
	case pb.L4Protocol_L4_PROTOCOL_UDP:
		return 17
	case pb.L4Protocol_L4_PROTOCOL_ICMP:
		return 1
	default:
		return 0
	}
}

// EventPayloadFromPolicyMatch converts a NetPolicyEvents PolicyMatchEvent into the
// JSON shape MicrosegHandler.Handle posts to clustermanager's /internal/microseg/event.
func EventPayloadFromPolicyMatch(evt *pb.PolicyMatchEvent) any {
	return microsegEventPayload{
		Proto:      l4ProtocolToWireCode(evt.GetProtocol()),
		Action:     policyActionToWireCode(evt.GetAction()),
		Direction:  flowDirectionToWireCode(evt.GetDirection()),
		SrcPort:    int(evt.GetSrcPort()),
		DstPort:    int(evt.GetDstPort()),
		SrcIP:      evt.GetSrcIp(),
		DstIP:      evt.GetDstIp(),
		PolicyName: evt.GetPolicyName(),
	}
}
