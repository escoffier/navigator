package fileters

import (
	"encoding/json"
	"gitlab.com/piccolo_su/vegeta/cmd/image-validate/pkg/validator"
	v1 "k8s.io/api/core/v1"
	"testing"
)

func Test_filterChain_Process(t *testing.T) {
	type fields struct {
		podFilters []PodValidator
	}
	type args struct {
		pod   *v1.Pod
		param ValidatingParameters
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name:   "test1",
			fields: fields{podFilters: []PodValidator{&validator.PodValidator{}}},
			args: args{pod: &v1.Pod{}, param: ValidatingParameters{
				Namespace: "",
				Kind:      "",
			}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &filterChain{
				PodValidators: tt.fields.podFilters,
			}
			raw, _ := json.Marshal(tt.args.pod)
			if err := c.Validate(tt.args.param, raw); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
