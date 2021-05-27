package image

import "testing"

func Test_urlSplit(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "1",
			args: args{s: "https://registry.a.com"},
			want: "registry.a.com",
		},
		{
			name: "2",
			args: args{s: " http://registry.b.com"},
			want: "registry.b.com",
		},
		{
			name: "3",
			args: args{s: "registry.b.com"},
			want: "registry.b.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := removeProtocolPrefixIfHaving(tt.args.s); got != tt.want {
				t.Errorf("urlSplit() = %v, want %v", got, tt.want)
			}
		})
	}
}
