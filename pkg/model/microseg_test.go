package model

import "testing"

func TestGenID(t *testing.T) {
	type args struct {
		strs []string
	}
	tests := []struct {
		name string
		args args
		want uint32
	}{
		// TODO: Add test cases.
		{
			name: "test-1",
			args: args{
				strs: []string{"bcc679aa-748f-4791-b043-8f5a61894e14", "test", "ReplicaSet", "zfc-rss"},
			},
			want: 3988792820,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GenID(tt.args.strs...); got != tt.want {
				t.Errorf("GenID() = %v, want %v", got, tt.want)
			}
		})
	}
}
