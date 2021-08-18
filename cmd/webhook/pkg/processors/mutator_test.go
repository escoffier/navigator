package processors

import (
	"context"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"reflect"
	"testing"
	"time"
)

func Test_mutatorChain_mutatePod(t *testing.T) {
	type fields struct {
		podMutators []PodMutator
	}
	type args struct {
		ctx        context.Context
		parameters *MutatorParameters
		pod        *core.Pod
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pod := core.Pod{ObjectMeta: metav1.ObjectMeta{
		Name:                       "",
		GenerateName:               "",
		Namespace:                  "",
		UID:                        "",
		ResourceVersion:            "",
		Generation:                 0,
		CreationTimestamp:          metav1.Time{},
		DeletionTimestamp:          nil,
		DeletionGracePeriodSeconds: nil,
		Labels:                     nil,
		Annotations:                nil,
		OwnerReferences:            nil,
		Finalizers:                 nil,
		ClusterName:                "",
	}}

	//m := microsegmutator.MicroSegMutator{}

	tests := []struct {
		name   string
		fields fields
		args   args
		want   []byte
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			//fields: fields{podMutators: {}},
			args: args{
				ctx:        ctx,
				parameters: nil,
				pod:        &pod,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mutatorChain{
				podMutators: tt.fields.podMutators,
			}
			if got := m.mutatePod(tt.args.ctx, tt.args.parameters, tt.args.pod); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mutatePod() = %v, want %v", got, tt.want)
			}
		})
	}
}
