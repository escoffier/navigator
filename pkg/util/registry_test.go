package util

import "testing"

func TestGetImageUrl(t *testing.T) {
	type args struct {
		image string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "test-1",
			args:    args{image: "registry.t-appagile.com/tensorsecurity/tensorsec-daemon:testcn"},
			want:    "registry.t-appagile.com",
			wantErr: false,
		},
		{
			name:    "test-docker-hub",
			args:    args{image: "busybox:1.28.4"},
			want:    "",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetImageUrl(tt.args.image)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetImageUrl() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetImageUrl() got = %v, want %v", got, tt.want)
			}
		})
	}
}
