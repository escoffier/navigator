package util

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
		{
			name: "tst1",
			args: args{strs: []string{"11985ff9-f822-44e5-95e6-a687cc5f013c", "test-pro", "Deployment", "res-c2"}},
			want: 4070543860,
		},
		{
			name: "tst2",
			args: args{strs: []string{"11985ff9-f822-44e5-95e6-a687cc5f013c", "test-pro", "Deployment", "res-c1"}},
			want: 4120876717,
		},
		{
			name: "tst3",
			args: args{strs: []string{"8efd2a2d-8aa9-4b76-ba16-e1b22bf2d9d3", "default", "Deployment", "51c1c6-dddd"}},
			want: 4157165057,
		},
		{
			name: "tst3",
			args: args{strs: []string{"8efd2a2d-8aa9-4b76-ba16-e1b22bf2d9d3", "default", "ReplicaSet", "51c1c6-dddd-674775f5d4"}},
			want: 2415580570,
		},
		{
			name: "tst4",
			args: args{strs: []string{"c35d049a-ea07-4107-8ad9-a95adce38413", "default", "Deployment", "51c1c6-eeeee1111"}},
			want: 3197592375,
		},
		{
			name: "tst5",
			args: args{strs: []string{"e886669a-96c8-426a-be5d-f9018e8f2b5f", "default", "Deployment", "alpine"}},
			want: 4041538280,
		},
		{
			name: "tst6",
			args: args{strs: []string{"e886669a-96c8-426a-be5d-f9018e8f2b5f", "default", "Pod", "alpine"}},
			want: 787884076,
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
