package microseg

import (
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

// ruleGroupToPayload converts an in-memory NetworkPolicyRuleGroup (computed by
// generateRules/caculatePolicyNodeRules*, unchanged by this migration) into
// the gRPC wire payload pushed to daemon.
func ruleGroupToPayload(rg *crdv1alpha1.NetworkPolicyRuleGroup) *pb.NetworkPolicyRuleGroupPayload {
	payload := &pb.NetworkPolicyRuleGroupPayload{
		Name:     rg.Name,
		Policy:   rg.Spec.Policy,
		NodeName: rg.Spec.NodeName,
	}
	for _, r := range rg.Spec.Rules {
		payload.Rules = append(payload.Rules, nodeRuleToPayload(r))
	}
	return payload
}

func nodeRuleToPayload(r crdv1alpha1.NodeRule) *pb.MicrosegNodeRule {
	out := &pb.MicrosegNodeRule{
		Name:      r.Name,
		Priority:  int32(r.Priority),
		Protocol:  r.Protocol,
		Direction: r.Direction,
		Action:    r.Action,
	}
	for _, p := range r.Ports {
		port := &pb.MicrosegPort{}
		if p.Protocol != nil {
			port.Protocol = string(*p.Protocol)
		}
		if p.Port != nil {
			port.Port = p.Port.String()
		}
		if p.EndPort != nil {
			port.EndPort = *p.EndPort
		}
		out.Ports = append(out.Ports, port)
	}
	for _, a := range r.ToAddresses {
		out.ToAddresses = append(out.ToAddresses, addressToPayload(a))
	}
	for _, b := range r.ToIPBlock {
		out.ToIPBlock = append(out.ToIPBlock, &pb.MicrosegIPBlock{CIDR: b.CIDR})
	}
	for _, a := range r.FromAddress {
		out.FromAddress = append(out.FromAddress, addressToPayload(a))
	}
	for _, b := range r.FromIPBlock {
		out.FromIPBlock = append(out.FromIPBlock, &pb.MicrosegIPBlock{CIDR: b.CIDR})
	}
	if r.Http != nil {
		out.Http = &pb.MicrosegHttp{Method: r.Http.Method, Path: r.Http.Path, Host: r.Http.Host}
	}
	return out
}

func addressToPayload(a crdv1alpha1.Address) *pb.MicrosegAddress {
	out := &pb.MicrosegAddress{IP: a.IP}
	if a.PodReference != nil {
		out.PodNamespace = a.PodReference.Namespace
		out.PodName = a.PodReference.Name
	}
	return out
}
