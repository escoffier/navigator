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
		want2 string
		want3 bool
	}{
		{
			name: "1",
			args: args{
				image: "harbor.a.com/tensor/a:latest",
			},
			want:  "harbor.a.com",
			want1: "/tensor/a",
			want2: "latest",
			want3: true,
		},
		{
			name: "2",
			args: args{
				image: "harbor.a.com/tensor/a/b:latest",
			},
			want:  "harbor.a.com",
			want1: "/tensor/a/b",
			want2: "",
		},
		{
			name: "3",
			args: args{
				image: "harbor.a.com/tensor/a/b:latest/aa",
			},
			want:  "harbor.a.com",
			want1: "/tensor/a/b",
			want2: "latest/aa",
			want3: true,
		},
		{
			name: "4",
			args: args{
				image: "harbor.a.com/tensor/a/b",
			},
			want:  "",
			want1: "",
			want2: "",
			want3: false,
		},
		{
			name: "5",
			args: args{
				image: "harbor.a.comtensorab:latest",
			},
			want:  "",
			want1: "",
			want2: "",
			want3: false,
		},
		{
			name: "6",
			args: args{
				image: "10.253.148.253:31994/secure-idss/cluster-manager:2.8.1",
			},
			want:  "10.253.148.253:31994/secure-idss/",
			want1: "cluster-manager",
			want2: "2.8.1",
			want3: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2, got3 := GetImagePrefixAndPostFixFrom(tt.args.image)
			if got != tt.want {
				t.Errorf("GetImagePrefixAndPostFixFrom() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("GetImagePrefixAndPostFixFrom() got1 = %v, want %v", got1, tt.want1)
			}
			if got2 != tt.want2 {
				t.Errorf("GetImagePrefixAndPostFixFrom() got2 = %v, want %v", got2, tt.want2)
			}
			if got3 != tt.want3 {
				t.Errorf("GetImagePrefixAndPostFixFrom() got3 = %v, want %v", got3, tt.want3)
			}
		})
	}
}
