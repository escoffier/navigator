package imagetrust

import (
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	v1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"sync"
	"testing"
)

func TestClusterManager_syncK8sClient(t *testing.T) {
	type fields struct {
		clientMap map[string]*kubernetes.Clientset
		in        v1.SecretInformer
		//secretInformers map[string]corev1.SecretInformer
		stopChans map[string]chan struct{}
		rdb       *rdbtools.GormWrapper
		RWMutex   sync.RWMutex
	}
	type args struct {
		clusters []*model.TensorCluster
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "test -1",
			fields: fields{
				clientMap: map[string]*kubernetes.Clientset{"111": nil, "222": nil, "333": nil, "444": nil, "555": nil},
				in:        nil,
				stopChans: nil,
				rdb:       nil,
				RWMutex:   sync.RWMutex{},
			},
			args: args{clusters: []*model.TensorCluster{
				{Key: "111"},
				{Key: "333"},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ClusterManager{
				clientMap: tt.fields.clientMap,
				in:        tt.fields.in,
				stopChans: tt.fields.stopChans,
				rdb:       tt.fields.rdb,
				RWMutex:   tt.fields.RWMutex,
			}

			m.syncK8sClient(tt.args.clusters)
			t.Logf("%+v", m.clientMap)
		})
	}
}
