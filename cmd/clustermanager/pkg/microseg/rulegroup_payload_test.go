package microseg

import (
	"testing"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

func Test_ruleGroupToPayload(t *testing.T) {
	port := intstr.FromInt(80)
	protocol := crdv1alpha1.Protocol("TCP")
	endPort := int32(90)

	rg := &crdv1alpha1.NetworkPolicyRuleGroup{
		ObjectMeta: v1.ObjectMeta{Name: "policy-node1"},
		Spec: crdv1alpha1.NetworkPolicyRuleGroupSpec{
			Policy:   "policy",
			NodeName: "node1",
			Rules: []crdv1alpha1.NodeRule{{
				Name: "rule1", Priority: 100, Protocol: "TCP", Direction: "ingress", Action: "Allow",
				Ports:       []crdv1alpha1.NetworkPolicyPort{{Protocol: &protocol, Port: &port, EndPort: &endPort}},
				FromAddress: []crdv1alpha1.Address{{IP: "10.0.0.1", PodReference: &crdv1alpha1.EntityReference{Namespace: "ns", Name: "pod-a"}}},
				ToAddresses: []crdv1alpha1.Address{{IP: "10.0.0.2"}},
				FromIPBlock: []crdv1alpha1.IPBlock{{CIDR: "10.0.1.0/24"}},
				ToIPBlock:   []crdv1alpha1.IPBlock{{CIDR: "10.0.2.0/24"}},
				Http:        &crdv1alpha1.Http{Method: "GET", Path: "/health", Host: "svc"},
			}},
		},
	}

	payload := ruleGroupToPayload(rg)

	if payload.GetName() != "policy-node1" || payload.GetPolicy() != "policy" || payload.GetNodeName() != "node1" {
		t.Fatalf("payload fields mismatch: %+v", payload)
	}
	if len(payload.GetRules()) != 1 {
		t.Fatalf("Rules = %d, want 1", len(payload.GetRules()))
	}
	r := payload.GetRules()[0]
	if r.GetName() != "rule1" || r.GetPriority() != 100 || r.GetAction() != "Allow" {
		t.Errorf("rule fields mismatch: %+v", r)
	}
	if len(r.GetPorts()) != 1 || r.GetPorts()[0].GetProtocol() != "TCP" || r.GetPorts()[0].GetPort() != "80" || r.GetPorts()[0].GetEndPort() != 90 {
		t.Errorf("Ports mismatch: %+v", r.GetPorts())
	}
	if len(r.GetFromAddress()) != 1 || r.GetFromAddress()[0].GetIP() != "10.0.0.1" ||
		r.GetFromAddress()[0].GetPodNamespace() != "ns" || r.GetFromAddress()[0].GetPodName() != "pod-a" {
		t.Errorf("FromAddress mismatch: %+v", r.GetFromAddress())
	}
	if len(r.GetToAddresses()) != 1 || r.GetToAddresses()[0].GetIP() != "10.0.0.2" {
		t.Errorf("ToAddresses mismatch: %+v", r.GetToAddresses())
	}
	if len(r.GetFromIPBlock()) != 1 || r.GetFromIPBlock()[0].GetCIDR() != "10.0.1.0/24" {
		t.Errorf("FromIPBlock mismatch: %+v", r.GetFromIPBlock())
	}
	if len(r.GetToIPBlock()) != 1 || r.GetToIPBlock()[0].GetCIDR() != "10.0.2.0/24" {
		t.Errorf("ToIPBlock mismatch: %+v", r.GetToIPBlock())
	}
	if r.GetHttp().GetHost() != "svc" {
		t.Errorf("Http mismatch: %+v", r.GetHttp())
	}
}
