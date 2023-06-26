package types

import (
	"reflect"
	"testing"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var np1 = `apiVersion: crd.antrea.io/v1alpha1
kind: ClusterNetworkPolicy
metadata:
  name: acnp-appliedto-per-rule
spec:
  priority: 1
  ingress:
  - action: Drop
    appliedTo:
    - podSelector:
        matchLabels:
          app: httpbin
    from:
    - podSelector:
       matchLabels:
         app: sleep
  - action: Drop
    appliedTo:
    - podSelector:
        matchLabels:
          app: db-restricted-east
    from:
    - podSelector:
        matchLabels:
          app: client-west`

func TestNewGroupSelector(t *testing.T) {
	type args struct {
		podSelector       *v1.LabelSelector
		namespaceSelector *v1.LabelSelector
	}

	lableSelector := &v1.LabelSelector{
		MatchLabels: map[string]string{"tier": "backend", "app": "database"},
	}

	selecotr, _ := v1.LabelSelectorAsSelector(lableSelector)
	tests := []struct {
		name string
		args args
		want *GroupSelector
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			args: args{
				podSelector: &v1.LabelSelector{
					MatchLabels: map[string]string{"tier": "backend", "app": "database"},
				},
				// namespaceSelector: &v1.LabelSelector{
				// 	MatchLabels: map[string]string{},
				// },
			},
			want: &GroupSelector{
				PodSeletor: selecotr,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewGroupSelector(tt.args.podSelector, tt.args.namespaceSelector); !reflect.DeepEqual(got, tt.want) {
				t.Log(got.PodSeletor.String())
				t.Errorf("NewGroupSelector() = %v, want %v", got, tt.want)
			}
		})
	}
}
