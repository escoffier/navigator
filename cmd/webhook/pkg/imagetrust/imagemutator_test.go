package imagetrust

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"

	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
)

func Test_patchImageDigest(t *testing.T) {
	type args struct {
		imageDigest *ImageDigest
	}
	tests := []struct {
		name string
		args args
		want []*processors.Patch
	}{
		{
			name: "test-1",
			args: args{imageDigest: &ImageDigest{
				InitContainerImages: []string{"abc:122222", "hhhhh:6788"},
				ContainerImages:     []string{"def:345555"},
			}},
			want: []*processors.Patch{
				{
					Op:    "replace",
					Path:  "/spec/initContainers/0/image",
					Value: "abc:122222",
				},
				{
					Op:    "replace",
					Path:  "/spec/initContainers/1/image",
					Value: "hhhhh:6788",
				},
				{
					Op:    "replace",
					Path:  "/spec/containers/0/image",
					Value: "def:345555",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := patchImageDigest(tt.args.imageDigest); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("patchImageDigest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func setUpServer() {
	server := http.Server{Addr: ":8080"}

	mutex := http.NewServeMux()
	mutex.HandleFunc("/imageDigest", func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil {
			return
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return
		}

		var imageReq ImageTagReq
		err = json.Unmarshal(body, &imageReq)
		if err != nil {
			return
		}

		var imageResp ImageDigestResp
		imageResp.InitContainerImages = []string{"abc:122222", "hhhhh:22333333"}
		imageResp.ContainerImages = []string{"eeee:5678"}

		resp, err := json.Marshal(&imageResp)
		if err != nil {
			return
		}
		w.Write(resp)
	})
	server.Handler = mutex

	err := server.ListenAndServe()
	if err != nil {
		return
	}
}

func Test_replaceTagWithDigest(t *testing.T) {
	type args struct {
		image  string
		digest string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test-1",
			args: args{
				image:  "docker.io/istio/examples-bookinfo-productpage-v1:1.15.0",
				digest: "111122222",
			},
			want: "docker.io/istio/examples-bookinfo-productpage-v1:111122222",
		},
		{
			name: "test-2",
			args: args{
				image:  "docker.io/istio/examples-bookinfo-productpage-v1",
				digest: "111122222",
			},
			want: "docker.io/istio/examples-bookinfo-productpage-v1",
		},
		{
			name: "test-3",
			args: args{
				image:  "",
				digest: "111122222",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := replaceTagWithDigest(tt.args.image, tt.args.digest); got != tt.want {
				t.Errorf("replaceTagWithDigest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getImageDigestFromHarbor(t *testing.T) {

	type args struct {
		in0    context.Context
		image  string
		secret *ImageRepoSecret
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test-1",
			args: args{image: "registry.t-appagile.com/tensorsecurity/tensorsec-operator:latest",
				secret: &ImageRepoSecret{
					user:     "admin",
					password: "Hrbr12@Tensor.*#)",
				}},
			want: "",
		},
		{
			name: "test-2",
			args: args{
				in0:    context.TODO(),
				image:  "docker.io/istio/examples-bookinfo-productpage-v1:1.15.0",
				secret: nil,
			},
		},
		{
			name: "test-busybox",
			args: args{
				in0:    context.TODO(),
				image:  "busybox:1.28.4",
				secret: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			if got = getImageDigestFromHarbor(tt.args.in0, tt.args.image, tt.args.secret); got != tt.want {

				t.Errorf("getImageDigestFromHarbor() = %v, want %v", got, tt.want)
			}
			t.Log(got)
		})
	}
}
