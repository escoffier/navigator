package clusterserver

import (
	"testing"
)

func Test_getClusterID(t *testing.T) {
	type args struct {
		clusterName   string
		apiServerAddr string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{
			name: "test-1",
			args: args{
				clusterName:   "Multi-Sit",
				apiServerAddr: "172.21.0.34:6443",
			},
			want: "3871160486",
		},

		{
			name: "test-2",
			args: args{
				clusterName:   "Multi-Sit",
				apiServerAddr: "https://172.21.0.34:6443",
			},
			want: "3871160486",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getClusterID(tt.args.clusterName, tt.args.apiServerAddr); got != tt.want {
				t.Errorf("getClusterID() = %v, want %v", got, tt.want)
			}
		})
	}
}
