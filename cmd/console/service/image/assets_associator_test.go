package image

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func Test_getFullRepoNameTagFromContainer(t *testing.T) {
	type args struct {
		container *corev1.ContainerStatus
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want1 string
	}{
		{
			name: "1",
			args: args{
				container: &corev1.ContainerStatus{
					Image: "192.168.1.203:5000/tensorsec-console:latest",
				},
			},
			want:  "tensorsec-console",
			want1: "latest",
		},
		{
			name: "2",
			args: args{
				container: &corev1.ContainerStatus{
					Image: "registry.com/tensorsec/tensorsec-console:latest",
				},
			},
			want:  "tensorsec/tensorsec-console",
			want1: "latest",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := getFullRepoNameTagFromContainer(tt.args.container)
			if got != tt.want {
				t.Errorf("getFullRepoNameTagFromContainer() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("getFullRepoNameTagFromContainer() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
