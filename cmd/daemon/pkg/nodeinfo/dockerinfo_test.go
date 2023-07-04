package nodeinfo

import (
	"context"
	"fmt"
	"testing"

	"github.com/docker/docker/client"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/containerassets"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/microseg"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	corev1 "k8s.io/api/core/v1"
)

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

type fakeStore struct {
	cache map[string]string
}

func (s *fakeStore) GetPodOwner(namespace, name string) (string, string, error) {
	return "", "", fmt.Errorf("pod %s/%s not found", namespace, name)
}

func (s *fakeStore) GetPod(namespace, name string) (*corev1.Pod, error) {
	return nil, fmt.Errorf("pod %s/%s not found", namespace, name)
}

func TestDockerInfoManager_processEvents(t *testing.T) {
	type fields struct {
		dockerCli     *client.Client
		hostIP        string
		hostName      string
		containerData map[string]int64
		handlers      []ContainerEventHandler
		agent         *containerassets.Agent
		store         containerassets.PodCache
		clusterKey    string
		policyCli     microseg.PolicyClient
	}
	type args struct {
		ctx       context.Context
		container *model.TensorRawContainer
		action    string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "pod-nil",
			fields: fields{
				store: &fakeStore{},
			},
			args: args{
				ctx: context.Background(),
				container: &model.TensorRawContainer{
					Namespace: "ns1",
					Name:      "httpbin",
				},
				action: "create",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DockerInfoManager{
				dockerCli:     tt.fields.dockerCli,
				hostIP:        tt.fields.hostIP,
				hostName:      tt.fields.hostName,
				containerData: tt.fields.containerData,
				handlers:      tt.fields.handlers,
				agent:         tt.fields.agent,
				store:         tt.fields.store,
				clusterKey:    tt.fields.clusterKey,
				policyCli:     tt.fields.policyCli,
			}
			d.processEvents(tt.args.ctx, tt.args.container, tt.args.action)
		})
	}
}
