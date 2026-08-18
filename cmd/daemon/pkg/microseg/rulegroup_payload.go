package microseg

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

// payloadToRuleGroup adapts a gRPC-pushed rule group payload back into the
// existing crdv1alpha1.NetworkPolicyRuleGroup shape, so buildPolicyRuleMessage*/
// syncPolicy/checkSync/splitPolicyRules (written against the k8s CRD) keep
// working unmodified regardless of whether the data came from a k8s informer
// or this stream-based transport.
func payloadToRuleGroup(payload *pb.NetworkPolicyRuleGroupPayload) *crdv1alpha1.NetworkPolicyRuleGroup {
	rg := &crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: payload.GetName()},
		Spec: crdv1alpha1.NetworkPolicyRuleGroupSpec{
			Policy:   payload.GetPolicy(),
			NodeName: payload.GetNodeName(),
		},
	}
	for _, r := range payload.GetRules() {
		rg.Spec.Rules = append(rg.Spec.Rules, payloadToNodeRule(r))
	}
	return rg
}

func payloadToNodeRule(r *pb.MicrosegNodeRule) crdv1alpha1.NodeRule {
	out := crdv1alpha1.NodeRule{
		Name:      r.GetName(),
		Priority:  int(r.GetPriority()),
		Protocol:  r.GetProtocol(),
		Direction: r.GetDirection(),
		Action:    r.GetAction(),
	}
	for _, p := range r.GetPorts() {
		port := crdv1alpha1.NetworkPolicyPort{}
		if p.GetProtocol() != "" {
			proto := crdv1alpha1.Protocol(p.GetProtocol())
			port.Protocol = &proto
		}
		if p.GetPort() != "" {
			v := intstr.Parse(p.GetPort())
			port.Port = &v
		}
		if p.GetEndPort() != 0 {
			endPort := p.GetEndPort()
			port.EndPort = &endPort
		}
		out.Ports = append(out.Ports, port)
	}
	for _, a := range r.GetToAddresses() {
		out.ToAddresses = append(out.ToAddresses, payloadToAddress(a))
	}
	for _, b := range r.GetToIPBlock() {
		out.ToIPBlock = append(out.ToIPBlock, crdv1alpha1.IPBlock{CIDR: b.GetCIDR()})
	}
	for _, a := range r.GetFromAddress() {
		out.FromAddress = append(out.FromAddress, payloadToAddress(a))
	}
	for _, b := range r.GetFromIPBlock() {
		out.FromIPBlock = append(out.FromIPBlock, crdv1alpha1.IPBlock{CIDR: b.GetCIDR()})
	}
	if r.GetHttp() != nil {
		out.Http = &crdv1alpha1.Http{Method: r.GetHttp().GetMethod(), Path: r.GetHttp().GetPath(), Host: r.GetHttp().GetHost()}
	}
	return out
}

func payloadToAddress(a *pb.MicrosegAddress) crdv1alpha1.Address {
	out := crdv1alpha1.Address{IP: a.GetIP()}
	if a.GetPodName() != "" || a.GetPodNamespace() != "" {
		out.PodReference = &crdv1alpha1.EntityReference{
			Namespace: a.GetPodNamespace(),
			Name:      a.GetPodName(),
		}
	}
	return out
}
