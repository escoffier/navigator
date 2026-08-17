package microseg

import (
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
)

// toPolicyAction mirrors ConvertRuleAction, net-policy.cpp:1397-1403:
// "Allow"/"Log" -> allow, "Alert" -> alert, anything else -> deny.
func toPolicyAction(action string) pb.PolicyAction {
	switch action {
	case "Allow", "Log":
		return pb.PolicyAction_POLICY_ACTION_ALLOW
	case "Alert":
		return pb.PolicyAction_POLICY_ACTION_ALERT
	default:
		return pb.PolicyAction_POLICY_ACTION_DENY
	}
}

// toFlowDirection mirrors ParseNetPolicy's direction parsing, net-policy.cpp:1498-1500:
// exact-match "ingress" (lowercase), anything else is egress.
func toFlowDirection(direction string) pb.FlowDirection {
	if direction == "ingress" {
		return pb.FlowDirection_FLOW_DIRECTION_INGRESS
	}
	return pb.FlowDirection_FLOW_DIRECTION_EGRESS
}

// toL4Protocol mirrors NetProtoConvert, net-policy.cpp:60-71.
func toL4Protocol(protocol string) pb.L4Protocol {
	switch protocol {
	case "TCP":
		return pb.L4Protocol_L4_PROTOCOL_TCP
	case "UDP":
		return pb.L4Protocol_L4_PROTOCOL_UDP
	case "ICMP":
		return pb.L4Protocol_L4_PROTOCOL_ICMP
	default:
		return pb.L4Protocol_L4_PROTOCOL_UNSPECIFIED
	}
}

func toPortRanges(ports []crdv1alpha1.NetworkPolicyPort) []*pb.PortRange {
	if len(ports) == 0 {
		return nil
	}
	out := make([]*pb.PortRange, 0, len(ports))
	for _, p := range ports {
		var port, endPort uint32
		if p.Port != nil {
			port = uint32(p.Port.IntValue())
		}
		if p.EndPort != nil {
			endPort = uint32(*p.EndPort)
		}
		out = append(out, &pb.PortRange{Port: port, EndPort: endPort})
	}
	return out
}

func toHttpMatchRules(rules []*crdv1alpha1.Http) []*pb.HttpMatchRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]*pb.HttpMatchRule, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		out = append(out, &pb.HttpMatchRule{Host: r.Host, Method: r.Method, Path: r.Path})
	}
	return out
}

func toAddressEndpoints(addrs []Address) []*pb.AddressEndpoint {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]*pb.AddressEndpoint, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, &pb.AddressEndpoint{Ip: a.IP, PodId: a.PodID})
	}
	return out
}

func toPolicyRuleSpecs(rules []NodeRule) []*pb.PolicyRuleSpec {
	if len(rules) == 0 {
		return nil
	}
	out := make([]*pb.PolicyRuleSpec, 0, len(rules))
	for _, r := range rules {
		out = append(out, &pb.PolicyRuleSpec{
			Action:        toPolicyAction(r.Action),
			Direction:     toFlowDirection(r.Direction),
			Protocol:      toL4Protocol(r.Protocol),
			HttpRules:     toHttpMatchRules(r.Http),
			FromAddresses: toAddressEndpoints(r.FromAddress),
			ToAddresses:   toAddressEndpoints(r.ToAddresses),
			Ports:         toPortRanges(r.Ports),
			Priority:      int32(r.Priority),
		})
	}
	return out
}
