package validator

import (
	"testing"
)

func Test_getContainerID(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			args: args{str: "docker://23526afd26ea860bfc1f2c729b0b67da8f57ade5388855c27283d20df56ba95e"},
			want: "23526afd26ea860bfc1f2c729b0b67da8f57ade5388855c27283d20df56ba95e",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getContainerID(tt.args.str); got != tt.want {
				t.Errorf("getContainerID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getImageTag(t *testing.T) {
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
			name: "test1",
			args: args{image: "kennethreitz/httpbin:latest"},
			want: "latest",
		},
		{
			name: "test2",
			args: args{image: "kennethreitz/httpbin:latest"},
			want: "bbbb",
		},
		{
			name: "test3",
			args: args{image: "kennethreitz/httpbinlatest"},
			want: "bbbb",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getImageTag(tt.args.image); got != tt.want {
				t.Errorf("getImageTag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getImageDigest(t *testing.T) {
	type args struct {
		imageID string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			args: args{imageID: "docker-pullable://kennethreitz/httpbin@sha256:599fe5e5073102dbb0ee3dbb65f049dab44fa9fc251f6835c9990f8fb196a72b"},
			want: "599fe5e5073102dbb0ee3dbb65f049dab44fa9fc251f6835c9990f8fb196a72b",
		},
		{
			name: "test2",
			args: args{imageID: "docker-pullable://kennethreitz/httpbin@sha256:599fe5e5073102dbb0ee3dbb65f049dab44fa9fc251f6835c9990f8fb196a72b"},
			want: "599fe5e5073102dbb0ee3dbb65f049dab44fa9fc251f6835c9990f8fb196a72b1",
		},
		{
			name: "test3",
			args: args{imageID: "docker-pullable://kennethreitz/httpbin@sha256:"},
			want: "599fe5e5073102dbb0ee3dbb65f049dab44fa9fc251f6835c9990f8fb196a72b",
		},
		{
			name: "test4",
			args: args{imageID: "docker-pullable://kennethreitz/httpbin@sha256"},
			want: "599fe5e5073102dbb0ee3dbb65f049dab44fa9fc251f6835c9990f8fb196a72b",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getImageDigest(tt.args.imageID); got != tt.want {
				t.Errorf("getImageDigest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getLibrary(t *testing.T) {
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
			name: "test1",
			args: args{image: "kennethreitz/ht1tpbin:latest"},
			want: "kennethreitz",
		},
		{
			name: "test2",
			args: args{image: "https://hub.docker.com/r/kennethreitz/htt1pbin:latest"},
			want: "kennethreitz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getLibrary(tt.args.image); got != tt.want {
				t.Errorf("getLibrary() = %v, want %v", got, tt.want)
			}
		})
	}
}
