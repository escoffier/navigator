package waf

import (
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	listerv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	crdfake "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/clientset/versioned/fake"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/informers/externalversions"
	listerv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/listers/waf.security.io/v1alpha1"
)

func TestWafController_loadConfig(t *testing.T) {
	client := fake.NewSimpleClientset()
	factory := informers.NewSharedInformerFactory(client, time.Hour)
	store := factory.Core().V1().ConfigMaps().Informer().GetStore()
	store.Add(v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "waf-rules",
			Namespace: "tensorsec",
		},
		Data: map[string]string{
			"config": `{"excluded_file_type":[".jpg",".png",".jpeg",".ico",".bmp",".svg",".gif",".exe",".pdf",".woff",".xml",".avi",".mp4",".flv",".js",".css"],"detect_headers":["host","url"]}`,
		},
	})

	crdClient := crdfake.NewSimpleClientset()
	crdFactory := externalversions.NewSharedInformerFactory(crdClient, time.Hour)

	type fields struct {
		wafServiceInformer cache.SharedIndexInformer
		configInformer     cache.SharedIndexInformer
		wafServiceLister   listerv1alpha1.ServiceLister
		configLister       listerv1.ConfigMapLister
		wafServiceSynced   cache.InformerSynced
		configSynced       cache.InformerSynced
		queue              workqueue.RateLimitingInterface
		rootNamespace      string
		wafRules           []Rule
	}
	type args struct {
		configMap *v1.ConfigMap
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test-1",
			fields: fields{
				wafServiceInformer: crdFactory.Waf().V1alpha1().Services().Informer(),
				configInformer:     factory.Core().V1().ConfigMaps().Informer(),
				configLister:       factory.Core().V1().ConfigMaps().Lister(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &WafController{
				wafServiceInformer: tt.fields.wafServiceInformer,
				configInformer:     tt.fields.configInformer,
				wafServiceLister:   tt.fields.wafServiceLister,
				configLister:       tt.fields.configLister,
				wafServiceSynced:   tt.fields.wafServiceSynced,
				configSynced:       tt.fields.configSynced,
				queue:              tt.fields.queue,
				rootNamespace:      tt.fields.rootNamespace,
				wafRules:           tt.fields.wafRules,
			}
			if err := c.loadConfig(tt.args.configMap); (err != nil) != tt.wantErr {
				t.Errorf("WafController.loadConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
