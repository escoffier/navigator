package k8s

import "testing"

func TestGetImagePrefixAndPostFixFrom(t *testing.T) {
	type args struct {
		image string
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want1 string
		want2 bool
	}{
		{
			name: "1",
			args: args{
				image: "harbor.a.com/tensor/a:latest",
			},
			want:  "harbor.a.com/tensor/",
			want1: "a:latest",
			want2: true,
		},
		{
			name: "2",
			args: args{
				image: "harbor.a.com/tensor/a/b:latest",
			},
			want:  "harbor.a.com/tensor/a/",
			want1: "b:latest",
			want2: true,
		},
		{
			name: "3",
			args: args{
				image: "harbor.a.com/tensor/a/b:latest/aa",
			},
			want:  "harbor.a.com/tensor/a/",
			want1: "b:latest/aa",
			want2: true,
		},
		{
			name: "4",
			args: args{
				image: "harbor.a.com/tensor/a/b",
			},
			want:  "",
			want1: "",
			want2: false,
		},
		{
			name: "5",
			args: args{
				image: "harbor.a.comtensorab:latest",
			},
			want:  "",
			want1: "",
			want2: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2 := GetImagePrefixAndPostFixFrom(tt.args.image)
			if got != tt.want {
				t.Errorf("GetImagePrefixAndPostFixFrom() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("GetImagePrefixAndPostFixFrom() got1 = %v, want %v", got1, tt.want1)
			}
			if got2 != tt.want2 {
				t.Errorf("GetImagePrefixAndPostFixFrom() got2 = %v, want %v", got2, tt.want2)
			}
		})
	}
}
