package nodeinfo

import "testing"

func Test_getImageDigest(t *testing.T) {
	type args struct {
		image string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{
			name: "sherlock-api",
			args: args{image: "harbor.tensorsecurity.com/tensorsecurity/sherlock-api@sha256:dae032a419eac63f3c7410b2c2eb864c484649e5e0a254a2895bed9bd8f3f346"},
			want: "sha256:dae032a419eac63f3c7410b2c2eb864c484649e5e0a254a2895bed9bd8f3f346",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getImageDigest(tt.args.image); got != tt.want {
				t.Errorf("getImageDigest() = %v, want %v", got, tt.want)
			}
		})
	}
}
