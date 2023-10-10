package imagetrust

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"

	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/utils"

	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
)

func Test_patchImageDigest(t *testing.T) {
	type args struct {
		imageDigest *PodImageDigest
	}
	tests := []struct {
		name string
		args args
		want []*processors.Patch
	}{
		{
			name: "test-1",
			args: args{imageDigest: &PodImageDigest{
				InitContainerImages: []ImageDigest{{Image: "", Digest: "abc:122222"}, {Digest: "hhhhh:6788"}},
				ContainerImages:     []ImageDigest{{Digest: "def:345555"}},
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
	server := http.Server{Addr: ":1999"}

	mutex := http.NewServeMux()
	mutex.HandleFunc("/imageDigest", func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil {
			return
		}
		body, err := io.ReadAll(r.Body)
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

	mutex.HandleFunc("/registries", func(w http.ResponseWriter, request *http.Request) {
		data := `{
    "apiVersion": "1.0",
    "data": {
        "startIndex": 0,
        "status": 0,
        "itemsPerPage": 10,
        "totalItems": 5,
        "items": [
            {
                "password": "Hrbr12@Tensor.*#)",
                "sync_interval": 0,
                "created_at": "2022-07-19T09:40:37.893Z",
                "deleted_at": 0,
                "id": 19,
                "description": "",
                "auth_str": "Basic ZGV2b3BzOkhyYnIxMkBUZW5zb3IuKiMp",
                "instance_id": "",
                "name": "hb-prod",
                "token": "",
                "use_type": 1,
                "last_sync_at": 1660288954,
                "access_secret": "",
                "reg_type": "harbor",
                "url": "https://harbor-prod.tensorsecurity.com",
                "username": "devops",
                "access_key": "",
                "region_id": "",
                "updated_at": "2022-08-12T07:22:34.2Z"
            },
            {
                "created_at": "2022-07-19T09:45:17.356Z",
                "username": "devops",
                "auth_str": "Basic ZGV2b3BzOkhyYnIxMkBUZW5zb3IuKiMp",
                "use_type": 1,
                "instance_id": "",
                "region_id": "",
                "name": "hellowrod",
                "url": "https://harbor.tensorsecurity.com",
                "updated_at": "2022-08-12T07:22:34.599Z",
                "last_sync_at": 1660288954,
                "access_secret": "",
                "deleted_at": 0,
                "id": 20,
                "password": "Hrbr12@Tensor.*#)",
                "token": "",
                "description": "",
                "sync_interval": 0,
                "reg_type": "harbor",
                "access_key": ""
            },
            {
                "deleted_at": 0,
                "reg_type": "registry-v2",
                "url": "http://console.tensorsecurity.com",
                "password": "Registry@Passw0rd",
                "description": "",
                "last_sync_at": 0,
                "created_at": "2022-07-19T09:49:19.477Z",
                "token": "",
                "sync_interval": 5,
                "instance_id": "",
                "region_id": "",
                "id": 23,
                "use_type": 1,
                "access_key": "",
                "updated_at": "2022-07-19T09:49:19.477Z",
                "name": "v2",
                "username": "registry",
                "auth_str": "Basic cmVnaXN0cnk6UmVnaXN0cnlAUGFzc3cwcmQ=",
                "access_secret": ""
            },
            {
                "url": "https://harbor-v1-sit.tensorsecurity.com",
                "password": "Hrbr12@Tensor.*#)",
                "access_key": "",
                "access_secret": "",
                "deleted_at": 0,
                "reg_type": "harbor",
                "description": "",
                "auth_str": "Basic ZGV2b3BzOkhyYnIxMkBUZW5zb3IuKiMp",
                "instance_id": "",
                "region_id": "",
                "updated_at": "2022-08-12T07:22:36.706Z",
                "id": 24,
                "token": "",
                "sync_interval": 0,
                "last_sync_at": 1660288956,
                "created_at": "2022-07-19T09:49:52.453Z",
                "name": "v1",
                "use_type": 1,
                "username": "devops"
            },
            {
                "updated_at": "2022-08-12T07:21:36.35Z",
                "url": "https://harbor-sample.tensorsecurity.cn",
                "description": "",
                "use_type": 1,
                "access_secret": "",
                "region_id": "",
                "id": 25,
                "reg_type": "harbor",
                "password": "Hrbr12@Tensor.*#)",
                "access_key": "",
                "created_at": "2022-08-05T07:56:28.405Z",
                "auth_str": "Basic ZGV2b3BzOkhyYnIxMkBUZW5zb3IuKiMp",
                "last_sync_at": 1660288896,
                "deleted_at": 0,
                "name": "harbor-sample",
                "username": "devops",
                "token": "",
                "sync_interval": 0,
                "instance_id": ""
            },
            {
                "url": "falut://harbor-sample.falut.tensorsecurity.cn" 
            }
        ]
    }
}`
		w.Write([]byte(data))
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
		secret *utils.ImageRepoSecret
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test-1",
			args: args{image: "harbor.tensorsecurity.com/tensorsec-operator:latest",
				secret: &utils.ImageRepoSecret{
					User:     "admin",
					Password: "Hrbr12@Tensor.*#)",
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
