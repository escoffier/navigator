package containerassets

import (
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"reflect"
	"testing"
)

func Test_mergeVolumeMounts(t *testing.T) {
	type args struct {
		kubeMounts   []model.Mounts
		dockerMounts []model.Mounts
	}
	tests := []struct {
		name string
		args args
		want []model.Mounts
	}{
		{
			name: "sub path",
			args: args{
				kubeMounts: []model.Mounts{
					{
						MountPath: "/usr/share/nginx/html",
						SubPath:   "html",
					},
				},
				dockerMounts: []model.Mounts{
					{
						Type:             "bind",
						SourcePath:       "/var/lib/kubelet/pods/54385695-4cd5-4408-8bb8-879f38230a11/volume-subpaths/vol-nginx-data/pod-nc1/0",
						MountPath:        "/usr/share/nginx/html",
						ReadOnly:         false,
						MountPropagation: "rprivate",
					},
					{
						Type:             "bind",
						SourcePath:       "/var/lib/kubelet/pods/54385695-4cd5-4408-8bb8-879f38230a11/volumes/kubernetes.io~projected/kube-api-access-45knf",
						MountPath:        "/var/run/secrets/kubernetes.io/serviceaccount",
						ReadOnly:         true,
						MountPropagation: "rprivate",
					},
				},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := utils.MergeVolumeMounts(tt.args.kubeMounts, tt.args.dockerMounts); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mergeVolumeMounts() = %v, want %v", got, tt.want)
			}
		})
	}
}
