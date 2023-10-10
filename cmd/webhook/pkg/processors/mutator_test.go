package processors

import (
	"context"
	"reflect"
	"testing"
	"time"

	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	}}

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "test1",
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
			got, err := m.mutatePod(tt.args.ctx, tt.args.parameters, tt.args.pod)
			if err != nil {
				t.Errorf("NetworkPolicyController.mutatePod() error = %v, wantErr %v", err, tt.wantErr)

			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mutatePod() = %v, want %v", got, tt.want)
			}
		})
	}
}
