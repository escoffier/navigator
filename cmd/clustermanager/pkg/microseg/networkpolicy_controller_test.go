package microseg

import (
	"context"
	"flag"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/microseg/types"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	listerv1 "k8s.io/client-go/listers/core/v1"
	dislisterv1 "k8s.io/client-go/listers/discovery/v1"
	dislisterv1beta1 "k8s.io/client-go/listers/discovery/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/client-go/util/workqueue"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/clientset/versioned"
	crdfake "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/clientset/versioned/fake"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/informers/externalversions"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/listers/microsegmentation.security.io/v1alpha1"
)

func TestNetworkPolicyController_caculatePolicy(t *testing.T) {
	type fields struct {
		policyInfomer     cache.SharedIndexInformer
		podInformer       cache.SharedIndexInformer
		namespaceInformer cache.SharedIndexInformer
		policyLister      v1alpha1.ClusterNetworkPolicyLister
		podLister         listerv1.PodLister
		namespaceLister   listerv1.NamespaceLister
		queue             workqueue.RateLimitingInterface
	}
	type args struct {
		cnp *crdv1alpha1.ClusterNetworkPolicy
	}

	client := fake.NewSimpleClientset()
	factory := informers.NewSharedInformerFactory(client, time.Hour)
	podStore := factory.Core().V1().Pods().Informer().GetIndexer()
	namespaceStore := factory.Core().V1().Namespaces().Informer().GetIndexer()
	pod := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "default",
			Name:      "test1",
			Labels: map[string]string{
				"app":  "http",
				"user": "robbie",
			},
		}}

	pod1 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "default",
			Name:      "test1",
			Labels: map[string]string{
				"app":  "http",
				"user": "robbie",
			},
		},
		Status: corev1.PodStatus{
			PodIP: "168.1.1.2",
		},
	}
	pod2 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns1",
			Name:      "test1",
			Labels: map[string]string{
				"app":  "frontend",
				"user": "robbie",
			},
		},
		Status: corev1.PodStatus{
			PodIP: "11.10.1.9",
		},
	}
	pod3 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns1",
			Name:      "mysql",
			Labels: map[string]string{
				"app":  "database",
				"user": "robbie",
			},
		},
		Status: corev1.PodStatus{
			PodIP: "10.10.1.9",
		},
	}
	pod4 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "default",
			Name:      "app-1",
			Labels: map[string]string{
				"app":  "worker",
				"user": "robbie",
			},
		},
		Status: corev1.PodStatus{
			PodIP: "110.10.1.18",
		},
	}
	pod5 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "default",
			Name:      "app-2",
			Labels: map[string]string{
				"app":  "test",
				"user": "robbie",
			},
		},
		Status: corev1.PodStatus{
			PodIP: "110.34.4.76",
		},
	}
	namespace1 := corev1.Namespace{
		ObjectMeta: v1.ObjectMeta{
			Name: "default",
			Labels: map[string]string{
				"tier":    "backend",
				"label-1": "value-1",
			},
		},
	}
	namespaceStore.Add(&namespace1)
	podStore.Add(&pod)
	podStore.Add(&pod1)
	podStore.Add(&pod2)
	podStore.Add(&pod3)
	podStore.Add(&pod4)
	podStore.Add(&pod5)

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *types.NetwokPolicy
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			fields: fields{
				podInformer:       factory.Core().V1().Pods().Informer(),
				namespaceInformer: factory.Core().V1().Namespaces().Informer(),
				podLister:         factory.Core().V1().Pods().Lister(),
				namespaceLister:   factory.Core().V1().Namespaces().Lister(),
			},
			args: args{
				cnp: &crdv1alpha1.ClusterNetworkPolicy{
					ObjectMeta: v1.ObjectMeta{
						Name: "cnp-1",
					},
					Spec: crdv1alpha1.ClusterNetworkPolicySpec{
						PodSelector: &v1.LabelSelector{MatchLabels: map[string]string{"app": "http"}},
						Ingress: []crdv1alpha1.Rule{
							{
								From: []crdv1alpha1.NetworkPolicyPeer{
									{
										PodSelector: &v1.LabelSelector{
											MatchLabels: map[string]string{
												"app": "frontend",
											},
										},
									},
								},
							},
						},
						Egress: []crdv1alpha1.Rule{
							{
								To: []crdv1alpha1.NetworkPolicyPeer{
									{
										PodSelector: &v1.LabelSelector{
											MatchLabels: map[string]string{
												"app": "database",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: &types.NetwokPolicy{
				AppliedAddress: []crdv1alpha1.Address{{IP: "168.1.1.2"}},
				Rules: []types.NetwokPolicyRule{
					{
						FromAddress: []crdv1alpha1.Address{{IP: "11.10.1.9"}},
					},
					{
						ToAddresses: []crdv1alpha1.Address{{IP: "10.10.1.9"}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test-2",
			fields: fields{
				podInformer:       factory.Core().V1().Pods().Informer(),
				namespaceInformer: factory.Core().V1().Namespaces().Informer(),
				podLister:         factory.Core().V1().Pods().Lister(),
				namespaceLister:   factory.Core().V1().Namespaces().Lister(),
			},
			args: args{
				cnp: &crdv1alpha1.ClusterNetworkPolicy{
					ObjectMeta: v1.ObjectMeta{
						Name: "namespace-policy",
					},
					Spec: crdv1alpha1.ClusterNetworkPolicySpec{
						PodSelector: &v1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}},
						Ingress: []crdv1alpha1.Rule{
							{
								From: []crdv1alpha1.NetworkPolicyPeer{
									{
										NamespaceSelector: &v1.LabelSelector{MatchLabels: map[string]string{"tier": "backend"}},
									},
								},
							},
						},
					},
				},
			},
			want: &types.NetwokPolicy{
				AppliedAddress: []crdv1alpha1.Address{{IP: "11.10.1.9"}},
				Rules: []types.NetwokPolicyRule{
					{
						FromAddress: []crdv1alpha1.Address{{IP: "110.10.1.18"}, {IP: "110.34.4.76"}, {IP: "168.1.1.2"}},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npc := &NetworkPolicyController{
				policyInfomer:     tt.fields.policyInfomer,
				podInformer:       tt.fields.podInformer,
				namespaceInformer: tt.fields.namespaceInformer,
				policyLister:      tt.fields.policyLister,
				podLister:         tt.fields.podLister,
				namespaceLister:   tt.fields.namespaceLister,
				queue:             tt.fields.queue,
			}
			got, err := npc.caculatePolicy(tt.args.cnp)
			if (err != nil) != tt.wantErr {
				t.Errorf("NetworkPolicyController.caculatePolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NetworkPolicyController.caculatePolicy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNetworkPolicyController_calulateAddress(t *testing.T) {
	type fields struct {
		policyInfomer     cache.SharedIndexInformer
		podInformer       cache.SharedIndexInformer
		namespaceInformer cache.SharedIndexInformer
		policyLister      v1alpha1.ClusterNetworkPolicyLister
		podLister         listerv1.PodLister
		namespaceLister   listerv1.NamespaceLister
		queue             workqueue.RateLimitingInterface
	}
	type args struct {
		podLabels       *v1.LabelSelector
		namespaceLabels *v1.LabelSelector
		group           string
	}

	client := fake.NewSimpleClientset()
	factory := informers.NewSharedInformerFactory(client, time.Hour)
	stopChan := make(chan struct{})
	factory.Start(stopChan)

	podStore := factory.Core().V1().Pods().Informer().GetIndexer()
	namespaceStore := factory.Core().V1().Namespaces().Informer().GetIndexer()
	pod1 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns1",
			Name:      "test1",
			Labels: map[string]string{
				"app":  "http",
				"user": "robbie",
			},
		},
		Status: corev1.PodStatus{
			PodIP: "168.1.1.2",
		},
	}
	pod2 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns1",
			Name:      "test11",
			Labels: map[string]string{
				"app":  "frontend",
				"user": "robbie",
			},
		},
		Status: corev1.PodStatus{
			PodIP: "10.10.1.9",
		},
	}
	pod3 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns1",
			Name:      "mysql",
			Labels: map[string]string{
				"app":  "database",
				"user": "robbie",
			},
		},
		Status: corev1.PodStatus{
			PodIP: "10.10.1.9",
		},
	}
	namespace1 := &corev1.Namespace{
		ObjectMeta: v1.ObjectMeta{
			Name: "ns1",
			Labels: map[string]string{
				"tier":    "backend",
				"label-1": "value-1",
			},
		},
	}
	namespaceStore.Add(namespace1)
	podStore.Add(&pod1)
	podStore.Add(&pod2)
	podStore.Add(&pod3)

	factory.WaitForCacheSync(stopChan)

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []crdv1alpha1.Address
		wantErr bool
	}{
		{
			name: "test1",
			fields: fields{
				podInformer:       factory.Core().V1().Pods().Informer(),
				namespaceInformer: factory.Core().V1().Namespaces().Informer(),
				podLister:         factory.Core().V1().Pods().Lister(),
				namespaceLister:   factory.Core().V1().Namespaces().Lister(),
			},
			args: args{
				podLabels: &v1.LabelSelector{
					MatchLabels: map[string]string{"app": "http"},
				},
				namespaceLabels: &v1.LabelSelector{
					MatchLabels: map[string]string{
						"tier": "backend",
					},
				},
			},
			want:    []crdv1alpha1.Address{{IP: "168.1.1.2", PodReference: podReference(&pod1)}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npc := &NetworkPolicyController{
				policyInfomer:     tt.fields.policyInfomer,
				podInformer:       tt.fields.podInformer,
				namespaceInformer: tt.fields.namespaceInformer,
				policyLister:      tt.fields.policyLister,
				podLister:         tt.fields.podLister,
				namespaceLister:   tt.fields.namespaceLister,
				queue:             tt.fields.queue,
			}
			got, err := npc.caculateAddress(tt.args.podLabels, tt.args.namespaceLabels, tt.args.group)
			if (err != nil) != tt.wantErr {
				t.Errorf("NetworkPolicyController.calulateAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NetworkPolicyController.calulateAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyIndex(t *testing.T) {
	client := crdfake.NewSimpleClientset()
	factory := externalversions.NewSharedInformerFactory(client, time.Hour)
	// factory := informers.NewSharedInformerFactory(client, time.Hour)
	stopChan := make(chan struct{})

	policyInfomer := factory.Microsegmentation().V1alpha1().ClusterNetworkPolicies().Informer()
	// policyInfomer.AddIndexers(cache.Indexers{"label-index": func(obj interface{}) ([]string, error) {
	// 	pol := obj.(*crdv1alpha1.ClusterNetworkPolicy)
	// 	var values []string
	// 	if pol.Spec.PodSelector != nil {
	// 		values = append(values, v1.FormatLabelSelector(pol.Spec.PodSelector))

	// 	}

	// 	return values, nil
	// }})
	policyInfomer.AddIndexers(cache.Indexers{"label-index": podLabelIndexFunc})

	factory.Start(stopChan)
	factory.WaitForCacheSync(stopChan)

	policyStore := factory.Microsegmentation().V1alpha1().ClusterNetworkPolicies().Informer().GetIndexer()
	policy1 := &crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "frontend-policy-1",
		},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			PodSelector: &v1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}},
			Ingress: []crdv1alpha1.Rule{
				{
					From: []crdv1alpha1.NetworkPolicyPeer{
						{
							NamespaceSelector: &v1.LabelSelector{MatchLabels: map[string]string{"tier": "backend"}},
						},
					},
				},
			},
			Egress: []crdv1alpha1.Rule{
				{
					To: []crdv1alpha1.NetworkPolicyPeer{
						{
							PodSelector: &v1.LabelSelector{MatchLabels: map[string]string{"app": "mysql"}},
						},
					},
				},
			},
		},
	}
	policy2 := &crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "frontend-policy-2",
		},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			PodSelector: &v1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}},
			Ingress: []crdv1alpha1.Rule{
				{
					From: []crdv1alpha1.NetworkPolicyPeer{
						{
							NamespaceSelector: &v1.LabelSelector{MatchLabels: map[string]string{"tier": "backend"}},
						},
					},
				},
			},
		},
	}
	policyStore.Add(policy1)
	policyStore.Add(policy2)
	t.Log("test end")

	// t.Errorf("keys: %v", policyInfomer.GetIndexer().ListKeys())

	t.Errorf("values %v", policyInfomer.GetIndexer().ListIndexFuncValues("label-index"))

	objs, err := policyInfomer.GetIndexer().ByIndex("label-index", v1.FormatLabelSelector(&v1.LabelSelector{
		MatchLabels: map[string]string{"app": "frontend"}}))
	if err != nil {
		t.Error(err)
		return
	}

	if len(objs) != 2 {
		t.Fatalf("should get 2 policies, but get %d", len(objs))
	}
	for _, obj := range objs {
		policy := obj.(*crdv1alpha1.ClusterNetworkPolicy)
		t.Log(policy.Name)
	}

}

func Test_getPodPolicyRelationShips(t *testing.T) {
	type args struct {
		policyLister    v1alpha1.ClusterNetworkPolicyLister
		namespaceLister listerv1.NamespaceLister
		pod             *corev1.Pod
	}
	crdClient := crdfake.NewSimpleClientset()
	crdFactory := externalversions.NewSharedInformerFactory(crdClient, time.Hour)

	client := fake.NewSimpleClientset()
	factory := informers.NewSharedInformerFactory(client, time.Hour)

	stopChan := make(chan struct{})
	factory.Start(stopChan)
	factory.WaitForCacheSync(stopChan)
	crdFactory.Start(stopChan)
	crdFactory.WaitForCacheSync(stopChan)

	policyInfomer := crdFactory.Microsegmentation().V1alpha1().ClusterNetworkPolicies().Informer()
	policyLister := crdFactory.Microsegmentation().V1alpha1().ClusterNetworkPolicies().Lister()

	namespaceLister := factory.Core().V1().Namespaces().Lister()

	factory.Core().V1().Namespaces().Informer().GetIndexer().Add(&corev1.Namespace{
		ObjectMeta: v1.ObjectMeta{
			Name: "ns-1",
			Labels: map[string]string{
				"tier": "backend",
			},
		},
	})

	factory.Core().V1().Namespaces().Informer().GetIndexer().Add(&corev1.Namespace{
		ObjectMeta: v1.ObjectMeta{
			Name: "ns-2",
			Labels: map[string]string{
				"tier": "front",
			},
		},
	})

	factory.Core().V1().Namespaces().Informer().GetIndexer().Add(&corev1.Namespace{
		ObjectMeta: v1.ObjectMeta{
			Name: "ns-storage",
			Labels: map[string]string{
				"tier": "storage",
			},
		},
	})

	policyInfomer.GetIndexer().Add(&crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "policy-1",
		},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			PodSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{"app": "httpbin"},
			},
		},
	})

	policyInfomer.GetIndexer().Add(&crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "policy-2",
		},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			PodSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{"tier": "backend"},
			},
		},
	})

	policyInfomer.GetIndexer().Add(&crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "policy-3",
		},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			PodSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{"app": "front"},
			},
		},
	})
	policyInfomer.GetIndexer().Add(&crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "policy-4",
		},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			PodSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{"app": "front"},
			},
		},
	})
	policyInfomer.GetIndexer().Add(&crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "policy-5",
		},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			NamespaceSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{"tier": "front"},
			},
		},
	})
	policyInfomer.GetIndexer().Add(&crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "policy-6",
		},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			NamespaceSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{"tier": "front"},
			},
		},
	})
	policyInfomer.GetIndexer().Add(&crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "policy-7",
		},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			NamespaceSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{"tier": "storage"},
			},
			Ingress: []crdv1alpha1.Rule{
				{
					From: []crdv1alpha1.NetworkPolicyPeer{
						{
							PodSelector: &v1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "web",
								},
							},
						},
					},
				},
			},
		},
	})
	policyInfomer.GetIndexer().Add(&crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "policy-8",
		},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			NamespaceSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{"tier": "storage"},
			},
			Egress: []crdv1alpha1.Rule{
				{
					To: []crdv1alpha1.NetworkPolicyPeer{
						{
							PodSelector: &v1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "outer",
								},
							},
						},
					},
				},
			},
		},
	})
	policyInfomer.GetIndexer().Add(&crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "policy-9",
		},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			NamespaceSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{"tier": "backend"},
			},
			Egress: []crdv1alpha1.Rule{
				{
					To: []crdv1alpha1.NetworkPolicyPeer{
						{
							NamespaceSelector: &v1.LabelSelector{
								MatchLabels: map[string]string{
									"tier": "storage",
								},
							},
						},
					},
				},
			},
		},
	})

	tests := []struct {
		name    string
		args    args
		want    sets.String
		wantErr bool
	}{
		{
			name: "test-pod-selecotr",
			args: args{
				policyLister:    policyLister,
				namespaceLister: namespaceLister,
				pod: &corev1.Pod{
					ObjectMeta: v1.ObjectMeta{
						Namespace: "ns-1",
						Name:      "httpbin",
						Labels: map[string]string{
							"app":  "httpbin",
							"tier": "backend",
						},
					},
				},
			},
			want:    sets.String{"policy-1": {}, "policy-2": {}, "policy-9": {}},
			wantErr: false,
		},
		{
			name: "test-ns-selecotr",
			args: args{
				policyLister:    policyLister,
				namespaceLister: namespaceLister,
				pod: &corev1.Pod{
					ObjectMeta: v1.ObjectMeta{
						Namespace: "ns-2",
						Name:      "httpbin",
						Labels: map[string]string{
							"tier": "backend",
						},
					},
				},
			},
			want:    sets.String{"policy-2": {}, "policy-5": {}, "policy-6": {}},
			wantErr: false,
		},
		{
			name: "test-pod-ingress-selecotr",
			args: args{
				policyLister:    policyLister,
				namespaceLister: namespaceLister,
				pod: &corev1.Pod{
					ObjectMeta: v1.ObjectMeta{
						Namespace: "ns-3",
						Name:      "httpbin",
						Labels: map[string]string{
							"app": "web",
						},
					},
				},
			},
			want:    sets.String{"policy-7": {}},
			wantErr: false,
		},
		{
			name: "test-pod-egress-selecotr",
			args: args{
				policyLister:    policyLister,
				namespaceLister: namespaceLister,
				pod: &corev1.Pod{
					ObjectMeta: v1.ObjectMeta{
						Namespace: "ns-3",
						Name:      "httpbin",
						Labels: map[string]string{
							"app": "outer",
						},
					},
				},
			},
			want:    sets.String{"policy-8": {}},
			wantErr: false,
		},
		{
			name: "test-ns-ns-selecotr",
			args: args{
				policyLister:    policyLister,
				namespaceLister: namespaceLister,
				pod: &corev1.Pod{
					ObjectMeta: v1.ObjectMeta{
						Namespace: "ns-storage",
						Name:      "dababase",
						Labels: map[string]string{
							"app": "outer",
						},
					},
				},
			},
			want:    sets.String{"policy-7": {}, "policy-8": {}, "policy-9": {}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getPodPolicyRelationShips(tt.args.policyLister, tt.args.namespaceLister, tt.args.pod)
			if (err != nil) != tt.wantErr {
				t.Errorf("getPodPolicyRelationShips() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getPodPolicyRelationShips() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNetworkPolicyController_caculateAddressMap(t *testing.T) {
	type fields struct {
		policyInfomer     cache.SharedIndexInformer
		podInformer       cache.SharedIndexInformer
		namespaceInformer cache.SharedIndexInformer
		policyLister      v1alpha1.ClusterNetworkPolicyLister
		podLister         listerv1.PodLister
		namespaceLister   listerv1.NamespaceLister
		queue             workqueue.RateLimitingInterface
	}
	type args struct {
		podLabels       *v1.LabelSelector
		namespaceLabels *v1.LabelSelector
		group           string
	}

	client := fake.NewSimpleClientset()
	factory := informers.NewSharedInformerFactory(client, time.Hour)
	stopChan := make(chan struct{})
	factory.Start(stopChan)
	factory.WaitForCacheSync(stopChan)

	podStore := factory.Core().V1().Pods().Informer().GetIndexer()
	namespaceStore := factory.Core().V1().Namespaces().Informer().GetIndexer()
	pod1 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "default",
			Name:      "test1",
			Labels: map[string]string{
				"app":  "http",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node1",
		},
		Status: corev1.PodStatus{
			PodIP: "168.1.1.2",
		},
	}
	pod2 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns2",
			Name:      "test1",
			Labels: map[string]string{
				"app":  "http",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node2",
		},
		Status: corev1.PodStatus{
			PodIP: "10.10.1.9",
		},
	}
	pod3 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns1",
			Name:      "mysql-1",
			Labels: map[string]string{
				"app":  "database",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node3",
		},
		Status: corev1.PodStatus{
			PodIP: "10.11.1.9",
		},
	}

	pod4 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns1",
			Name:      "mysql-2",
			Labels: map[string]string{
				"app":  "redis",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node3",
		},
		Status: corev1.PodStatus{
			PodIP: "189.11.1.9",
		},
	}
	pod5 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns1",
			Name:      "redis-1",
			Labels: map[string]string{
				"app":  "redis",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node5",
		},
		Status: corev1.PodStatus{
			PodIP: "178.11.1.9",
		},
	}
	namespace1 := corev1.Namespace{
		ObjectMeta: v1.ObjectMeta{
			Name: "ns1",
			Labels: map[string]string{
				"tier":    "backend",
				"label-1": "value-1",
			},
		},
	}
	namespaceStore.Add(&namespace1)
	podStore.Add(&pod1)
	podStore.Add(&pod2)
	podStore.Add(&pod3)
	podStore.Add(&pod4)
	podStore.Add(&pod5)

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    map[string][]crdv1alpha1.Address
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "test-1",
			fields: fields{
				podInformer:       factory.Core().V1().Pods().Informer(),
				namespaceInformer: factory.Core().V1().Namespaces().Informer(),
				podLister:         factory.Core().V1().Pods().Lister(),
				namespaceLister:   factory.Core().V1().Namespaces().Lister(),
			},
			args: args{
				podLabels: &v1.LabelSelector{
					MatchLabels: map[string]string{"app": "http"},
				},
			},
			want: map[string][]crdv1alpha1.Address{
				"node1": {{IP: "168.1.1.2", PodReference: podReference(&pod1)}},
				"node2": {{IP: "10.10.1.9", PodReference: podReference(&pod2)}},
			},
			wantErr: false,
		},
		{
			name: "test-2",
			fields: fields{
				podInformer:       factory.Core().V1().Pods().Informer(),
				namespaceInformer: factory.Core().V1().Namespaces().Informer(),
				podLister:         factory.Core().V1().Pods().Lister(),
				namespaceLister:   factory.Core().V1().Namespaces().Lister(),
			},
			args: args{
				namespaceLabels: &v1.LabelSelector{
					MatchLabels: map[string]string{"app": "redis"},
				},
			},
			want:    map[string][]crdv1alpha1.Address{},
			wantErr: false,
		},
		{
			name: "test-3",
			fields: fields{
				podInformer:       factory.Core().V1().Pods().Informer(),
				namespaceInformer: factory.Core().V1().Namespaces().Informer(),
				podLister:         factory.Core().V1().Pods().Lister(),
				namespaceLister:   factory.Core().V1().Namespaces().Lister(),
			},
			args: args{
				namespaceLabels: &v1.LabelSelector{
					MatchLabels: map[string]string{"tier": "backend"},
				},
			},
			want: map[string][]crdv1alpha1.Address{
				"node3": {{IP: "10.11.1.9", PodReference: podReference(&pod3)}, {IP: "189.11.1.9", PodReference: podReference(&pod4)}},
				"node5": {{IP: "178.11.1.9", PodReference: podReference(&pod5)}}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npc := &NetworkPolicyController{
				policyInfomer:     tt.fields.policyInfomer,
				podInformer:       tt.fields.podInformer,
				namespaceInformer: tt.fields.namespaceInformer,
				policyLister:      tt.fields.policyLister,
				podLister:         tt.fields.podLister,
				namespaceLister:   tt.fields.namespaceLister,
				queue:             tt.fields.queue,
			}
			got, err := npc.caculateAddressMap(tt.args.podLabels, tt.args.namespaceLabels, tt.args.group)
			if (err != nil) != tt.wantErr {
				t.Errorf("NetworkPolicyController.caculateAddressMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			eq := maps.EqualFunc(got, tt.want, func(v1 []crdv1alpha1.Address, v2 []crdv1alpha1.Address) bool {
				return slices.Equal(v1, v2)
			})
			// if !reflect.DeepEqual(got, tt.want) {
			if !eq {
				t.Errorf("NetworkPolicyController.caculateAddressMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNetworkPolicyController_caculateNodeRules(t *testing.T) {
	type fields struct {
		policyInfomer      cache.SharedIndexInformer
		podInformer        cache.SharedIndexInformer
		namespaceInformer  cache.SharedIndexInformer
		policyLister       v1alpha1.ClusterNetworkPolicyLister
		podLister          listerv1.PodLister
		namespaceLister    listerv1.NamespaceLister
		clusterGroupLister v1alpha1.ClusterWorkloadSetLister
		queue              workqueue.RateLimitingInterface
	}
	type args struct {
		cnp *crdv1alpha1.ClusterNetworkPolicy
	}

	client := fake.NewSimpleClientset()
	factory := informers.NewSharedInformerFactory(client, time.Hour)

	crdClient := crdfake.NewSimpleClientset()
	crdFactory := externalversions.NewSharedInformerFactory(crdClient, time.Hour)

	stopChan := make(chan struct{})
	factory.Start(stopChan)
	factory.WaitForCacheSync(stopChan)
	crdFactory.Start(stopChan)
	crdFactory.WaitForCacheSync(stopChan)

	podStore := factory.Core().V1().Pods().Informer().GetIndexer()
	namespaceStore := factory.Core().V1().Namespaces().Informer().GetIndexer()
	clusterGroupStore := crdFactory.Microsegmentation().V1alpha1().ClusterWorkloadSets().Informer().GetIndexer()

	pod1 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "default",
			Name:      "test1",
			Labels: map[string]string{
				"app":  "http",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node1",
		},
		Status: corev1.PodStatus{
			PodIP: "168.1.1.2",
		},
	}
	pod2 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns2",
			Name:      "test1",
			Labels: map[string]string{
				"app":  "http",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node2",
		},
		Status: corev1.PodStatus{
			PodIP: "10.10.1.9",
		},
	}
	pod3 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns1",
			Name:      "mysql-1",
			Labels: map[string]string{
				"app":  "database",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node3",
		},
		Status: corev1.PodStatus{
			PodIP: "10.11.1.9",
		},
	}

	pod4 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns1",
			Name:      "mysql-2",
			Labels: map[string]string{
				"app":  "redis",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node3",
		},
		Status: corev1.PodStatus{
			PodIP: "189.11.1.9",
		},
	}
	pod5 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns1",
			Name:      "redis-1",
			Labels: map[string]string{
				"app":  "redis",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node5",
		},
		Status: corev1.PodStatus{
			PodIP: "178.11.1.9",
		},
	}
	namespace1 := corev1.Namespace{
		ObjectMeta: v1.ObjectMeta{
			Name: "ns1",
			Labels: map[string]string{
				"tier":    "backend",
				"label-1": "value-1",
			},
		},
	}
	namespaceStore.Add(&namespace1)
	podStore.Add(&pod1)
	podStore.Add(&pod2)
	podStore.Add(&pod3)
	podStore.Add(&pod4)
	podStore.Add(&pod5)

	clusterGroupStore.Add(&crdv1alpha1.ClusterWorkloadSet{
		ObjectMeta: v1.ObjectMeta{
			Name: "cluster-group-1",
		},
		Spec: crdv1alpha1.ClusterWorkloadSetSpec{
			PodSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{"app": "http"},
			},
		},
	})

	clusterGroupStore.Add(&crdv1alpha1.ClusterWorkloadSet{
		ObjectMeta: v1.ObjectMeta{
			Name: "cluster-group-2",
		},
		Spec: crdv1alpha1.ClusterWorkloadSetSpec{
			PodSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{"app": "redis"},
			},
		},
	})

	action := crdv1alpha1.RuleActionAllow
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    map[string][]types.NodeRule
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "test-ingress",
			fields: fields{
				podInformer:       factory.Core().V1().Pods().Informer(),
				namespaceInformer: factory.Core().V1().Namespaces().Informer(),
				podLister:         factory.Core().V1().Pods().Lister(),
				namespaceLister:   factory.Core().V1().Namespaces().Lister(),
			},
			args: args{&crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{
					Name: "test-1",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					PodSelector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "http",
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &action,
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									NamespaceSelector: &v1.LabelSelector{
										MatchLabels: map[string]string{
											"tier": "backend",
										},
									},
								},
							},
						},
					},
				},
			}},
			want: map[string][]types.NodeRule{
				"node1": {
					{
						PolicyName:  "test-1",
						NodeName:    "node1",
						Priority:    0,
						Action:      "Allow",
						ToAddresses: []crdv1alpha1.Address{{IP: "168.1.1.2"}},
						FromAddress: []crdv1alpha1.Address{{IP: "10.11.1.9"}, {IP: "178.11.1.9"}, {IP: "189.11.1.9"}},
					},
				},
				"node2": {
					{
						PolicyName:  "test-1",
						NodeName:    "node2",
						Priority:    0,
						Action:      "Allow",
						ToAddresses: []crdv1alpha1.Address{{IP: "10.10.1.9"}},
						FromAddress: []crdv1alpha1.Address{{IP: "10.11.1.9"}, {IP: "178.11.1.9"}, {IP: "189.11.1.9"}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test-egress",
			fields: fields{
				podInformer:       factory.Core().V1().Pods().Informer(),
				namespaceInformer: factory.Core().V1().Namespaces().Informer(),
				podLister:         factory.Core().V1().Pods().Lister(),
				namespaceLister:   factory.Core().V1().Namespaces().Lister(),
			},
			args: args{&crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{
					Name: "test-egress",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					PodSelector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "http",
						},
					},
					Egress: []crdv1alpha1.Rule{
						{
							Action: &action,
							To: []crdv1alpha1.NetworkPolicyPeer{
								{
									NamespaceSelector: &v1.LabelSelector{
										MatchLabels: map[string]string{
											"tier": "backend",
										},
									},
								},
							},
						},
					},
				},
			}},
			want: map[string][]types.NodeRule{
				"node3": {
					{
						PolicyName:  "test-egress",
						NodeName:    "node3",
						Action:      "Allow",
						FromAddress: []crdv1alpha1.Address{{IP: "10.10.1.9"}, {IP: "168.1.1.2"}},
						ToAddresses: []crdv1alpha1.Address{{IP: "10.11.1.9"}, {IP: "189.11.1.9"}},
					},
				},
				"node5": {
					{
						PolicyName:  "test-egress",
						NodeName:    "node5",
						Action:      "Allow",
						FromAddress: []crdv1alpha1.Address{{IP: "10.10.1.9"}, {IP: "168.1.1.2"}},
						ToAddresses: []crdv1alpha1.Address{{IP: "178.11.1.9"}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test-group",
			fields: fields{
				podInformer:        factory.Core().V1().Pods().Informer(),
				namespaceInformer:  factory.Core().V1().Namespaces().Informer(),
				podLister:          factory.Core().V1().Pods().Lister(),
				namespaceLister:    factory.Core().V1().Namespaces().Lister(),
				clusterGroupLister: crdFactory.Microsegmentation().V1alpha1().ClusterWorkloadSets().Lister(),
			},
			args: args{&crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{
					Name: "group-policy",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					Group: "cluster-group-1",
					Ingress: []crdv1alpha1.Rule{
						{
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									Group: "cluster-group-2",
								},
							},
							Action: &action,
						},
					},
				},
			}},
			want: map[string][]types.NodeRule{
				"node1": {
					{
						PolicyName:  "group-policy",
						NodeName:    "node1",
						FromAddress: []crdv1alpha1.Address{{IP: "178.11.1.9"}, {IP: "189.11.1.9"}},
						ToAddresses: []crdv1alpha1.Address{{IP: "168.1.1.2"}},
						Action:      "Allow",
					},
				},
				"node2": {
					{
						PolicyName:  "group-policy",
						NodeName:    "node2",
						FromAddress: []crdv1alpha1.Address{{IP: "178.11.1.9"}, {IP: "189.11.1.9"}},
						ToAddresses: []crdv1alpha1.Address{{IP: "10.10.1.9"}},
						Action:      "Allow",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npc := &NetworkPolicyController{
				policyInfomer:      tt.fields.policyInfomer,
				podInformer:        tt.fields.podInformer,
				namespaceInformer:  tt.fields.namespaceInformer,
				policyLister:       tt.fields.policyLister,
				podLister:          tt.fields.podLister,
				namespaceLister:    tt.fields.namespaceLister,
				clusterGroupLister: tt.fields.clusterGroupLister,
				queue:              tt.fields.queue,
			}
			got, err := npc.caculateNodeRules(tt.args.cnp)
			if (err != nil) != tt.wantErr {
				t.Errorf("NetworkPolicyController.caculateNodeRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NetworkPolicyController.caculateNodeRules() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func Test_getNamespacePolicyRelationShips(t *testing.T) {
	type args struct {
		policyLister v1alpha1.ClusterNetworkPolicyLister
		namespace    *corev1.Namespace
	}
	crdClient := crdfake.NewSimpleClientset()
	crdFactory := externalversions.NewSharedInformerFactory(crdClient, time.Hour)

	client := fake.NewSimpleClientset()
	factory := informers.NewSharedInformerFactory(client, time.Hour)

	stopChan := make(chan struct{})
	factory.Start(stopChan)
	factory.WaitForCacheSync(stopChan)
	crdFactory.Start(stopChan)
	crdFactory.WaitForCacheSync(stopChan)

	policyStore := crdFactory.Microsegmentation().V1alpha1().ClusterNetworkPolicies().Informer().GetIndexer()
	policy1 := crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "policy-1",
		},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			NamespaceSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{
					"tier": "web",
				},
			},
			Ingress: []crdv1alpha1.Rule{
				{
					From: []crdv1alpha1.NetworkPolicyPeer{
						{
							NamespaceSelector: &v1.LabelSelector{
								MatchLabels: map[string]string{
									"tier": "front",
								},
							},
						},
					},
				},
			},
			Egress: []crdv1alpha1.Rule{
				{
					To: []crdv1alpha1.NetworkPolicyPeer{
						{
							NamespaceSelector: &v1.LabelSelector{
								MatchLabels: map[string]string{
									"tier": "database",
								},
							},
						},
					},
				},
			},
		},
	}

	policy2 := crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "policy-2",
		},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			NamespaceSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{"tier": "database"},
			},
		},
	}

	policyStore.Add(&policy1)
	policyStore.Add(&policy2)

	tests := []struct {
		name    string
		args    args
		want    sets.String
		wantErr bool
	}{
		{
			name: "test-1",
			args: args{
				policyLister: crdFactory.Microsegmentation().V1alpha1().ClusterNetworkPolicies().Lister(),
				namespace: &corev1.Namespace{
					ObjectMeta: v1.ObjectMeta{
						Name: "ns-1",
						Labels: map[string]string{
							"tier": "web",
						},
					},
				},
			},
			want:    sets.String{"policy-1": {}},
			wantErr: false,
		},
		{
			name: "test-ingress",
			args: args{
				policyLister: crdFactory.Microsegmentation().V1alpha1().ClusterNetworkPolicies().Lister(),
				namespace: &corev1.Namespace{
					ObjectMeta: v1.ObjectMeta{
						Name: "ns-1",
						Labels: map[string]string{
							"tier": "front",
						},
					},
				},
			},
			want:    sets.String{"policy-1": {}},
			wantErr: false,
		},
		{
			name: "test-egress",
			args: args{
				policyLister: crdFactory.Microsegmentation().V1alpha1().ClusterNetworkPolicies().Lister(),
				namespace: &corev1.Namespace{
					ObjectMeta: v1.ObjectMeta{
						Name: "ns-1",
						Labels: map[string]string{
							"tier": "database",
						},
					},
				},
			},
			want:    sets.String{"policy-1": {}, "policy-2": {}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getNamespacePolicyRelationShips(tt.args.policyLister, tt.args.namespace)
			if (err != nil) != tt.wantErr {
				t.Errorf("getNamespacePolicyRelationShips() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getNamespacePolicyRelationShips() = %v, want %v", got, tt.want)
			}
		})
	}
}

// func TestNetworkPolicyController_caculatePolicyNodeRules(t *testing.T) {
// 	type fields struct {
// 		clietset             *versioned.Clientset
// 		policyInfomer        cache.SharedIndexInformer
// 		podInformer          cache.SharedIndexInformer
// 		namespaceInformer    cache.SharedIndexInformer
// 		clusterGroupInformer cache.SharedIndexInformer
// 		policyLister         v1alpha1.ClusterNetworkPolicyLister
// 		podLister            listerv1.PodLister
// 		namespaceLister      listerv1.NamespaceLister
// 		clusterGroupLister   v1alpha1.MicrosegClusterGroupLister
// 		podSynced            cache.InformerSynced
// 		namepaceSynced       cache.InformerSynced
// 		clusterPolicySynced  cache.InformerSynced
// 		clusterGroupSynced   cache.InformerSynced
// 		queue                workqueue.RateLimitingInterface
// 	}
// 	type args struct {
// 		cnp *crdv1alpha1.ClusterNetworkPolicy
// 	}

// 	client := fake.NewSimpleClientset()
// 	factory := informers.NewSharedInformerFactory(client, time.Hour)

// 	crdClient := crdfake.NewSimpleClientset()
// 	crdFactory := externalversions.NewSharedInformerFactory(crdClient, time.Hour)

// 	stopChan := make(chan struct{})
// 	factory.Start(stopChan)
// 	factory.WaitForCacheSync(stopChan)
// 	crdFactory.Start(stopChan)
// 	crdFactory.WaitForCacheSync(stopChan)

// 	podStore := factory.Core().V1().Pods().Informer().GetIndexer()
// 	namespaceStore := factory.Core().V1().Namespaces().Informer().GetIndexer()
// 	// clusterGroupStore := crdFactory.Microsegmentation().V1alpha1().MicrosegClusterGroups().Informer().GetIndexer()

// 	pod1 := corev1.Pod{
// 		ObjectMeta: v1.ObjectMeta{
// 			Namespace: "default",
// 			Name:      "test1",
// 			Labels: map[string]string{
// 				"app":  "http",
// 				"user": "robbie",
// 			},
// 		},
// 		Spec: corev1.PodSpec{
// 			NodeName: "node1",
// 		},
// 		Status: corev1.PodStatus{
// 			PodIP: "168.1.1.2",
// 		},
// 	}
// 	pod2 := corev1.Pod{
// 		ObjectMeta: v1.ObjectMeta{
// 			Namespace: "ns2",
// 			Name:      "test1",
// 			Labels: map[string]string{
// 				"app":  "http",
// 				"user": "robbie",
// 			},
// 		},
// 		Spec: corev1.PodSpec{
// 			NodeName: "node2",
// 		},
// 		Status: corev1.PodStatus{
// 			PodIP: "10.10.1.9",
// 		},
// 	}
// 	pod3 := corev1.Pod{
// 		ObjectMeta: v1.ObjectMeta{
// 			Namespace: "ns1",
// 			Name:      "mysql-1",
// 			Labels: map[string]string{
// 				"app":  "database",
// 				"user": "robbie",
// 			},
// 		},
// 		Spec: corev1.PodSpec{
// 			NodeName: "node3",
// 		},
// 		Status: corev1.PodStatus{
// 			PodIP: "10.11.1.9",
// 		},
// 	}

// 	pod4 := corev1.Pod{
// 		ObjectMeta: v1.ObjectMeta{
// 			Namespace: "ns1",
// 			Name:      "mysql-2",
// 			Labels: map[string]string{
// 				"app":  "redis",
// 				"user": "robbie",
// 			},
// 		},
// 		Spec: corev1.PodSpec{
// 			NodeName: "node3",
// 		},
// 		Status: corev1.PodStatus{
// 			PodIP: "189.11.1.9",
// 		},
// 	}
// 	pod5 := corev1.Pod{
// 		ObjectMeta: v1.ObjectMeta{
// 			Namespace: "ns1",
// 			Name:      "redis-1",
// 			Labels: map[string]string{
// 				"app":  "redis",
// 				"user": "robbie",
// 			},
// 		},
// 		Spec: corev1.PodSpec{
// 			NodeName: "node5",
// 		},
// 		Status: corev1.PodStatus{
// 			PodIP: "178.11.1.9",
// 		},
// 	}
// 	namespace1 := corev1.Namespace{
// 		ObjectMeta: v1.ObjectMeta{
// 			Name: "ns1",
// 			Labels: map[string]string{
// 				"tier":    "backend",
// 				"label-1": "value-1",
// 			},
// 		},
// 	}
// 	namespaceStore.Add(&namespace1)
// 	podStore.Add(&pod1)
// 	podStore.Add(&pod2)
// 	podStore.Add(&pod3)
// 	podStore.Add(&pod4)
// 	podStore.Add(&pod5)

// 	action := crdv1alpha1.RuleActionAllow
// 	tests := []struct {
// 		name    string
// 		fields  fields
// 		args    args
// 		want    map[string]*crdv1alpha1.NetworkPolicyRuleSlice
// 		wantErr bool
// 	}{
// 		{
// 			name: "test-ingress",
// 			fields: fields{
// 				podInformer:       factory.Core().V1().Pods().Informer(),
// 				namespaceInformer: factory.Core().V1().Namespaces().Informer(),
// 				podLister:         factory.Core().V1().Pods().Lister(),
// 				namespaceLister:   factory.Core().V1().Namespaces().Lister(),
// 			},
// 			args: args{&crdv1alpha1.ClusterNetworkPolicy{
// 				ObjectMeta: v1.ObjectMeta{
// 					Name: "test-1",
// 				},
// 				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
// 					PodSelector: &v1.LabelSelector{
// 						MatchLabels: map[string]string{
// 							"app": "http",
// 						},
// 					},
// 					Ingress: []crdv1alpha1.Rule{
// 						{
// 							Action: &action,
// 							From: []crdv1alpha1.NetworkPolicyPeer{
// 								{
// 									NamespaceSelector: &v1.LabelSelector{
// 										MatchLabels: map[string]string{
// 											"tier": "backend",
// 										},
// 									},
// 								},
// 							},
// 						},
// 					},
// 				},
// 			}},
// 			want: map[string]*crdv1alpha1.NetworkPolicyRuleSlice{
// 				"node1": {},
// 				"node2": {},
// 			},
// 			wantErr: false,
// 		},
// 		{
// 			name: "test-ipblock",
// 			fields: fields{
// 				podInformer:       factory.Core().V1().Pods().Informer(),
// 				namespaceInformer: factory.Core().V1().Namespaces().Informer(),
// 				podLister:         factory.Core().V1().Pods().Lister(),
// 				namespaceLister:   factory.Core().V1().Namespaces().Lister(),
// 			},
// 			args: args{&crdv1alpha1.ClusterNetworkPolicy{
// 				ObjectMeta: v1.ObjectMeta{
// 					Name: "test-ipblock",
// 				},
// 				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
// 					PodSelector: &v1.LabelSelector{
// 						MatchLabels: map[string]string{
// 							"app": "http",
// 						},
// 					},
// 					Ingress: []crdv1alpha1.Rule{
// 						{
// 							Action: &action,
// 							From: []crdv1alpha1.NetworkPolicyPeer{
// 								{
// 									IPBlock: &crdv1alpha1.IPBlock{
// 										CIDR: "192.168.23.12/24",
// 									},
// 								},
// 							},
// 						},
// 					},
// 					Egress: []crdv1alpha1.Rule{
// 						{
// 							Action: &action,
// 							To: []crdv1alpha1.NetworkPolicyPeer{
// 								{
// 									IPBlock: &crdv1alpha1.IPBlock{
// 										CIDR: "11.23.22.1/12",
// 									},
// 								},
// 							},
// 						},
// 					},
// 				},
// 			}},
// 			want: map[string]*crdv1alpha1.NetworkPolicyRuleSlice{
// 				"node1": {},
// 				"node2": {},
// 			},
// 			wantErr: false,
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			npc := &NetworkPolicyController{
// 				clietset:             tt.fields.clietset,
// 				policyInfomer:        tt.fields.policyInfomer,
// 				podInformer:          tt.fields.podInformer,
// 				namespaceInformer:    tt.fields.namespaceInformer,
// 				clusterGroupInformer: tt.fields.clusterGroupInformer,
// 				policyLister:         tt.fields.policyLister,
// 				podLister:            tt.fields.podLister,
// 				namespaceLister:      tt.fields.namespaceLister,
// 				clusterGroupLister:   tt.fields.clusterGroupLister,
// 				podSynced:            tt.fields.podSynced,
// 				namepaceSynced:       tt.fields.namepaceSynced,
// 				clusterPolicySynced:  tt.fields.clusterPolicySynced,
// 				clusterGroupSynced:   tt.fields.clusterGroupSynced,
// 				queue:                tt.fields.queue,
// 			}
// 			got, err := npc.caculatePolicyNodeRules(tt.args.cnp)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("NetworkPolicyController.caculatePolicyNodeRules() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}

// 			if tt.name == "test-ipblock" {
// 				r1, ok := got["node1"]
// 				if !ok {
// 					t.Error("no rules within node1")
// 					return
// 				}
// 				// t.Errorf("got rule %+v", *r1)
// 				if r1.Spec.Rules[0].FromIPBlock.CIDR != "192.168.23.12/24" {
// 					t.Errorf("cidr : %s, want: %s", r1.Spec.Rules[0].FromIPBlock.CIDR, "192.168.23.12/24")
// 					return
// 				}
// 				if r1.Spec.Rules[1].ToIPBlock.CIDR != "11.23.22.1/12" {
// 					t.Errorf("cidr : %s, want: %s", r1.Spec.Rules[0].FromIPBlock.CIDR, "11.23.22.1/12")
// 					return
// 				}
// 				// for node, _ := range tt.want {
// 				// 	r, ok := got[node]
// 				// 	if !ok {
// 				// 		t.Errorf("got nil node rule, want %v", node)
// 				// 		continue
// 				// 	}
// 				// 	ipblock := crdv1alpha1.IPBlock{
// 				// 		CIDR: "192.168.23.12/24",
// 				// 	}
// 				// 	if r.Spec.Rules[0].FromIPBlock != nil {
// 				// 		if !reflect.DeepEqual(*r.Spec.Rules[0].FromIPBlock, ipblock) {
// 				// 			t.Errorf("NetworkPolicyController.caculatePolicyNodeRules() ipblock = %+v, want %+v", *r.Spec.Rules[0].ToIPBlock, ipblock)
// 				// 		}
// 				// 	}

// 				// 	if r.Spec.Rules[0].ToIPBlock == nil {
// 				// 		t.Error("egress to ipblock should not be nil")
// 				// 		return
// 				// 	}
// 				// 	if !reflect.DeepEqual(*r.Spec.Rules[0].FromIPBlock, ipblock) {
// 				// 		t.Errorf("NetworkPolicyController.caculatePolicyNodeRules() ipblock = %+v, want %+v", *r.Spec.Rules[0].ToIPBlock, ipblock)
// 				// 	}

// 				// 	// if !reflect.DeepEqual(*r, *rule) {
// 				// 	// 	t.Errorf("NetworkPolicyController.caculatePolicyNodeRules() = %+v, want %+v", *r, *rule)
// 				// 	// }
// 				// }
// 			}

// 			// if !reflect.DeepEqual(got, tt.want) {
// 			// 	t.Errorf("NetworkPolicyController.caculatePolicyNodeRules() = %+v, want %+v", got, tt.want)
// 			// }
// 		})
// 	}
// }

func TestCreateCRD(t *testing.T) {
	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	// create the clientset
	clientset, err := assets.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	_, err = clientset.TensorClientset.MicrosegmentationV1alpha1().ClusterWorkloadSets().Create(context.TODO(),
		&crdv1alpha1.ClusterWorkloadSet{
			ObjectMeta: v1.ObjectMeta{
				Name: "test-111",
			},
		}, v1.CreateOptions{})
	if err != nil {
		t.Error(err)
	}

	_, err = clientset.TensorClientset.MicrosegmentationV1alpha1().NetworkPolicyRuleGroups().Create(context.TODO(),
		&crdv1alpha1.NetworkPolicyRuleGroup{}, v1.CreateOptions{})
	if err != nil {
		t.Error(err)
		return
	}

}

func TestNetworkPolicyController_caculatePolicyNodeRules1(t *testing.T) {
	type fields struct {
		clietset              *versioned.Clientset
		policyInfomer         cache.SharedIndexInformer
		podInformer           cache.SharedIndexInformer
		namespaceInformer     cache.SharedIndexInformer
		endpointsliceInformer cache.SharedIndexInformer
		clusterGroupInformer  cache.SharedIndexInformer
		policyLister          v1alpha1.ClusterNetworkPolicyLister
		podLister             listerv1.PodLister
		namespaceLister       listerv1.NamespaceLister
		serviceLister         listerv1.ServiceLister
		endpointsliceLister   dislisterv1.EndpointSliceLister
		clusterGroupLister    v1alpha1.ClusterWorkloadSetLister
		ruleGroupLister       v1alpha1.NetworkPolicyRuleGroupLister
		podSynced             cache.InformerSynced
		namepaceSynced        cache.InformerSynced
		clusterPolicySynced   cache.InformerSynced
		clusterGroupSynced    cache.InformerSynced
		ruleGroupSynced       cache.InformerSynced
		queue                 workqueue.RateLimitingInterface
	}
	type args struct {
		cnp *crdv1alpha1.ClusterNetworkPolicy
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    map[string]*crdv1alpha1.NetworkPolicyRuleGroup
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npc := &NetworkPolicyController{
				clietset:              tt.fields.clietset,
				policyInfomer:         tt.fields.policyInfomer,
				podInformer:           tt.fields.podInformer,
				namespaceInformer:     tt.fields.namespaceInformer,
				endpointsliceInformer: tt.fields.endpointsliceInformer,
				clusterGroupInformer:  tt.fields.clusterGroupInformer,
				policyLister:          tt.fields.policyLister,
				podLister:             tt.fields.podLister,
				namespaceLister:       tt.fields.namespaceLister,
				serviceLister:         tt.fields.serviceLister,
				endpointsliceLister:   tt.fields.endpointsliceLister,
				clusterGroupLister:    tt.fields.clusterGroupLister,
				ruleGroupLister:       tt.fields.ruleGroupLister,
				podSynced:             tt.fields.podSynced,
				namepaceSynced:        tt.fields.namepaceSynced,
				clusterPolicySynced:   tt.fields.clusterPolicySynced,
				clusterGroupSynced:    tt.fields.clusterGroupSynced,
				ruleGroupSynced:       tt.fields.ruleGroupSynced,
				queue:                 tt.fields.queue,
			}
			got, err := npc.caculatePolicyNodeRules(tt.args.cnp)
			if (err != nil) != tt.wantErr {
				t.Errorf("NetworkPolicyController.caculatePolicyNodeRules1() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NetworkPolicyController.caculatePolicyNodeRules1() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getServicePort(t *testing.T) {
	type args struct {
		pod         *corev1.Pod
		svcPorts    []corev1.ServicePort
		svc         *corev1.Service
		policyPorts []crdv1alpha1.NetworkPolicyPort
	}
	tcp := crdv1alpha1.ProtocolTCP
	port80 := intstr.FromInt(80)
	port81 := intstr.FromInt(81)

	port8000 := intstr.FromInt(8000)
	port8100 := intstr.FromInt(8100)
	tests := []struct {
		name string
		args args
		want []crdv1alpha1.NetworkPolicyPort
	}{
		{
			name: "test-1",
			args: args{
				svc: &corev1.Service{
					ObjectMeta: v1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "ns-1",
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Protocol:   corev1.ProtocolTCP,
								Port:       8000,
								TargetPort: intstr.FromInt(80),
							},
							{
								Port:       8100,
								TargetPort: intstr.FromInt(81),
							},
						},
					},
				},
				svcPorts: []corev1.ServicePort{
					{
						Protocol:   corev1.ProtocolTCP,
						Port:       8000,
						TargetPort: intstr.FromInt(80),
					},
					{
						Port:       8100,
						TargetPort: intstr.FromInt(81),
					},
				},
				policyPorts: []crdv1alpha1.NetworkPolicyPort{
					{
						Protocol: &tcp,
						Port:     &port80,
					},
					{
						Port: &port81,
					},
				},
			},
			want: []crdv1alpha1.NetworkPolicyPort{
				{
					Protocol: &tcp,
					Port:     &port8000,
				},
				{
					Protocol: &tcp,
					Port:     &port8100,
				},
			},
		},
		{
			name: "test-all-ports",
			args: args{
				svc: &corev1.Service{
					ObjectMeta: v1.ObjectMeta{
						Namespace: "ns-2",
						Name:      "svc-2",
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Protocol:   corev1.ProtocolTCP,
								Port:       8000,
								TargetPort: intstr.FromInt(80),
							},
							{
								Port:       8100,
								TargetPort: intstr.FromInt(81),
							},
						},
					},
				},
				svcPorts: []corev1.ServicePort{
					{
						Protocol:   corev1.ProtocolTCP,
						Port:       8000,
						TargetPort: intstr.FromInt(80),
					},
					{
						Port:       8100,
						TargetPort: intstr.FromInt(81),
					},
				},
				policyPorts: []crdv1alpha1.NetworkPolicyPort{},
			},
			want: []crdv1alpha1.NetworkPolicyPort{
				{
					Protocol: &tcp,
					Port:     &port8000,
				},
				{
					Protocol: &tcp,
					Port:     &port8100,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getServicePort(tt.args.pod, tt.args.svc, tt.args.policyPorts)
			if *got[0].Port != *tt.want[0].Port || *got[0].Protocol != *tt.want[0].Protocol {
				t.Errorf("getServicePort got.port: %v, want port %v", *got[0].Port, *tt.want[0].Port)
			}

			if *got[1].Port != *tt.want[1].Port || *got[1].Protocol != *tt.want[1].Protocol {
				t.Errorf("getServicePort got.port: %v, want port %v", *got[0].Port, *tt.want[0].Port)
			}

			// if got := getServicePort(tt.args.svcPorts, tt.args.policyPorts); !reflect.DeepEqual(got, tt.want) {
			// 	t.Errorf("getServicePort() = %v, want %v", got, tt.want)
			// }
		})
	}
}

func TestNetworkPolicyController_getRelatedServiceAddr(t *testing.T) {
	type fields struct {
		clietset              *versioned.Clientset
		policyInfomer         cache.SharedIndexInformer
		podInformer           cache.SharedIndexInformer
		namespaceInformer     cache.SharedIndexInformer
		endpointsliceInformer cache.SharedIndexInformer
		clusterGroupInformer  cache.SharedIndexInformer
		policyLister          v1alpha1.ClusterNetworkPolicyLister
		podLister             listerv1.PodLister
		namespaceLister       listerv1.NamespaceLister
		serviceLister         listerv1.ServiceLister
		endpointsliceLister   dislisterv1.EndpointSliceLister
		clusterGroupLister    v1alpha1.ClusterWorkloadSetLister
		ruleGroupLister       v1alpha1.NetworkPolicyRuleGroupLister
		podSynced             cache.InformerSynced
		namepaceSynced        cache.InformerSynced
		clusterPolicySynced   cache.InformerSynced
		clusterGroupSynced    cache.InformerSynced
		ruleGroupSynced       cache.InformerSynced
		queue                 workqueue.RateLimitingInterface
	}
	type args struct {
		podLabels       *v1.LabelSelector
		namespaceLabels *v1.LabelSelector
		group           string
		policyPorts     []crdv1alpha1.NetworkPolicyPort
	}
	client := fake.NewSimpleClientset()
	factory := informers.NewSharedInformerFactory(client, time.Hour)

	crdClient := crdfake.NewSimpleClientset()
	crdFactory := externalversions.NewSharedInformerFactory(crdClient, time.Hour)

	stopChan := make(chan struct{})
	factory.Start(stopChan)
	factory.WaitForCacheSync(stopChan)
	crdFactory.Start(stopChan)
	crdFactory.WaitForCacheSync(stopChan)

	podStore := factory.Core().V1().Pods().Informer().GetIndexer()
	// namespaceStore := factory.Core().V1().Namespaces().Informer().GetIndexer()
	serviceStore := factory.Core().V1().Services().Informer().GetIndexer()

	serviceStore.Add(&corev1.Service{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns-1",
			Name:      "httb-1",
			Labels: map[string]string{
				"app": "web",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "web"},
			Ports: []corev1.ServicePort{
				{
					Port:       8000,
					TargetPort: intstr.FromInt(80),
				},
			},
			ClusterIP: "99.11.2.2",
		},
	})

	serviceStore.Add(&corev1.Service{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns-1",
			Name:      "httb-2",
			Labels: map[string]string{
				"app": "web",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "web"},
			Ports: []corev1.ServicePort{
				{
					Port:       8000,
					TargetPort: intstr.FromInt(80),
				},
			},
			ClusterIP: "99.11.12.56",
		},
	})

	podStore.Add(&corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns-1",
			Name:      "httb-1",
			Labels: map[string]string{
				"app": "web",
			},
		},
		Status: corev1.PodStatus{PodIP: "11.22.22.22"},
	})

	podStore.Add(&corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns-1",
			Name:      "httb-2",
			Labels: map[string]string{
				"app":   "web",
				"groou": "another",
			},
		},
		Status: corev1.PodStatus{PodIP: "31.32.32.22"},
	})
	port60 := intstr.FromInt(60)
	// port80 := intstr.FromInt(80)
	port8000 := intstr.FromInt(8000)

	var port10000 int32 = 10000
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []endPoint
		wantErr bool
	}{
		{
			name: "test-1",
			fields: fields{
				podInformer:       factory.Core().V1().Pods().Informer(),
				namespaceInformer: factory.Core().V1().Namespaces().Informer(),
				podLister:         factory.Core().V1().Pods().Lister(),
				namespaceLister:   factory.Core().V1().Namespaces().Lister(),
				serviceLister:     factory.Core().V1().Services().Lister(),
			},
			args: args{
				podLabels: &v1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
				policyPorts: []crdv1alpha1.NetworkPolicyPort{
					{
						Port:    &port60,
						EndPort: &port10000,
					},
				},
			},
			want: []endPoint{
				{
					Address: "99.11.12.56",
					Ports: []crdv1alpha1.NetworkPolicyPort{
						{Port: &port8000},
					},
				},
				{
					Address: "99.11.2.2",
					Ports: []crdv1alpha1.NetworkPolicyPort{
						{Port: &port8000},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npc := &NetworkPolicyController{
				clietset:              tt.fields.clietset,
				policyInfomer:         tt.fields.policyInfomer,
				podInformer:           tt.fields.podInformer,
				namespaceInformer:     tt.fields.namespaceInformer,
				endpointsliceInformer: tt.fields.endpointsliceInformer,
				clusterGroupInformer:  tt.fields.clusterGroupInformer,
				policyLister:          tt.fields.policyLister,
				podLister:             tt.fields.podLister,
				namespaceLister:       tt.fields.namespaceLister,
				serviceLister:         tt.fields.serviceLister,
				endpointsliceLister:   tt.fields.endpointsliceLister,
				clusterGroupLister:    tt.fields.clusterGroupLister,
				ruleGroupLister:       tt.fields.ruleGroupLister,
				podSynced:             tt.fields.podSynced,
				namepaceSynced:        tt.fields.namepaceSynced,
				clusterPolicySynced:   tt.fields.clusterPolicySynced,
				clusterGroupSynced:    tt.fields.clusterGroupSynced,
				ruleGroupSynced:       tt.fields.ruleGroupSynced,
				queue:                 tt.fields.queue,
			}
			got, err := npc.getRelatedServiceAddr(tt.args.podLabels, tt.args.namespaceLabels, tt.args.group, tt.args.policyPorts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NetworkPolicyController.getRelatedServiceAddr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i, ep := range got {
				if ep.Address != tt.want[i].Address {
					t.Errorf("cluster ip = %s, want : %s", ep.Address, tt.want[i].Address)
				}
				if !reflect.DeepEqual(ep.Ports[0].Port, tt.want[i].Ports[0].Port) {
					// if ep.ports[0].Port.String() != tt.want[i].ports[0].Port.String() {
					t.Errorf("port: %s, want: %s", ep.Ports[0].Port.String(), tt.want[i].Ports[0].Port.String())
				}
			}
			// if !reflect.DeepEqual(got, tt.want) {
			// 	t.Errorf("NetworkPolicyController.getRelatedServiceAddr() = %v, want %v", got, tt.want)
			// }
		})
	}
}

func TestNetworkPolicyController_caculatePolicyAllNodeRules(t *testing.T) {
	type fields struct {
		clietset                   *versioned.Clientset
		policyInfomer              cache.SharedIndexInformer
		podInformer                cache.SharedIndexInformer
		namespaceInformer          cache.SharedIndexInformer
		endpointsliceInformer      cache.SharedIndexInformer
		serviceInformer            cache.SharedIndexInformer
		clusterGroupInformer       cache.SharedIndexInformer
		policyLister               v1alpha1.ClusterNetworkPolicyLister
		podLister                  listerv1.PodLister
		namespaceLister            listerv1.NamespaceLister
		serviceLister              listerv1.ServiceLister
		endpointsliceLister        dislisterv1.EndpointSliceLister
		endpointsliceListerv1beta1 dislisterv1beta1.EndpointSliceLister
		clusterGroupLister         v1alpha1.ClusterWorkloadSetLister
		ruleGroupLister            v1alpha1.NetworkPolicyRuleGroupLister
		podSynced                  cache.InformerSynced
		namepaceSynced             cache.InformerSynced
		clusterPolicySynced        cache.InformerSynced
		clusterGroupSynced         cache.InformerSynced
		ruleGroupSynced            cache.InformerSynced
		queue                      workqueue.RateLimitingInterface
		pod2Policy                 map[string]string
	}
	type args struct {
		cnp *crdv1alpha1.ClusterNetworkPolicy
	}

	client := fake.NewSimpleClientset()
	factory := informers.NewSharedInformerFactory(client, time.Hour)

	crdClient := crdfake.NewSimpleClientset()
	crdFactory := externalversions.NewSharedInformerFactory(crdClient, time.Hour)

	stopChan := make(chan struct{})
	factory.Start(stopChan)
	factory.WaitForCacheSync(stopChan)
	crdFactory.Start(stopChan)
	crdFactory.WaitForCacheSync(stopChan)

	podStore := factory.Core().V1().Pods().Informer().GetIndexer()
	namespaceStore := factory.Core().V1().Namespaces().Informer().GetIndexer()
	clusterGroupStore := crdFactory.Microsegmentation().V1alpha1().ClusterWorkloadSets().Informer().GetIndexer()

	pod1 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "default",
			Name:      "test1",
			Labels: map[string]string{
				"app":  "http",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node1",
		},
		Status: corev1.PodStatus{
			PodIP: "168.1.1.2",
		},
	}
	pod2 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns2",
			Name:      "test1",
			Labels: map[string]string{
				"app":  "http",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node2",
		},
		Status: corev1.PodStatus{
			PodIP: "10.10.1.9",
		},
	}
	pod3 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns1",
			Name:      "mysql-1",
			Labels: map[string]string{
				"app":  "database",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node3",
		},
		Status: corev1.PodStatus{
			PodIP: "10.11.1.9",
		},
	}

	pod4 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns1",
			Name:      "mysql-2",
			Labels: map[string]string{
				"app":  "redis",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node3",
		},
		Status: corev1.PodStatus{
			PodIP: "189.11.1.9",
		},
	}
	pod5 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns1",
			Name:      "redis-1",
			Labels: map[string]string{
				"app":  "redis",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node5",
		},
		Status: corev1.PodStatus{
			PodIP: "178.11.1.9",
		},
	}

	pod21 := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns1",
			Name:      "test21",
			Labels: map[string]string{
				"app":  "test",
				"user": "robbie",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node2",
		},
		Status: corev1.PodStatus{
			PodIP: "10.10.11.99",
		},
	}

	namespace1 := corev1.Namespace{
		ObjectMeta: v1.ObjectMeta{
			Name: "ns1",
			Labels: map[string]string{
				"tier":    "backend",
				"label-1": "value-1",
			},
		},
	}
	namespaceStore.Add(&namespace1)
	podStore.Add(&pod1)
	podStore.Add(&pod2)
	podStore.Add(&pod3)
	podStore.Add(&pod4)
	podStore.Add(&pod5)
	podStore.Add(&pod21)

	clusterGroupStore.Add(&crdv1alpha1.ClusterWorkloadSet{
		ObjectMeta: v1.ObjectMeta{
			Name: "cluster-group-1",
		},
		Spec: crdv1alpha1.ClusterWorkloadSetSpec{
			PodSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{"app": "http"},
			},
		},
	})

	clusterGroupStore.Add(&crdv1alpha1.ClusterWorkloadSet{
		ObjectMeta: v1.ObjectMeta{
			Name: "cluster-group-2",
		},
		Spec: crdv1alpha1.ClusterWorkloadSetSpec{
			PodSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{"app": "redis"},
			},
		},
	})
	action := crdv1alpha1.RuleActionAllow

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    map[string]*crdv1alpha1.NetworkPolicyRuleGroup
		wantErr bool
	}{
		{
			name: "test-1",
			fields: fields{
				podLister:       factory.Core().V1().Pods().Lister(),
				namespaceLister: factory.Core().V1().Namespaces().Lister(),
			},
			args: args{&crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{
					Name: "test-1",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					PodSelector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "http",
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &action,
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									NamespaceSelector: &v1.LabelSelector{
										MatchLabels: map[string]string{
											"tier": "backend",
										},
									},
								},
							},
						},
					},
				},
			}},
		},
		{
			name: "test-egress",
			fields: fields{
				podInformer:       factory.Core().V1().Pods().Informer(),
				namespaceInformer: factory.Core().V1().Namespaces().Informer(),
				podLister:         factory.Core().V1().Pods().Lister(),
				namespaceLister:   factory.Core().V1().Namespaces().Lister(),
				serviceLister:     factory.Core().V1().Services().Lister(),
			},
			args: args{&crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{
					Name: "test-egress",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					PodSelector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "http",
						},
					},
					Egress: []crdv1alpha1.Rule{
						{
							Action: &action,
							To: []crdv1alpha1.NetworkPolicyPeer{
								{
									NamespaceSelector: &v1.LabelSelector{
										MatchLabels: map[string]string{
											"tier": "backend",
										},
									},
								},
							},
						},
					},
				},
			}},
			want: map[string]*crdv1alpha1.NetworkPolicyRuleGroup{
				"node3": {
					ObjectMeta: v1.ObjectMeta{
						Name: "test-egress",
					},
					Spec: crdv1alpha1.NetworkPolicyRuleGroupSpec{
						Policy:   "test-egress",
						NodeName: "node3",
						Rules: []crdv1alpha1.NodeRule{
							{
								Action:      "Allow",
								FromAddress: []crdv1alpha1.Address{{IP: "10.10.1.9"}, {IP: "168.1.1.2"}},
								ToAddresses: []crdv1alpha1.Address{{IP: "10.11.1.9"}, {IP: "189.11.1.9"}},
							},
						},
					},
				},
				"node5": {
					ObjectMeta: v1.ObjectMeta{
						Name: "test-egress",
					},
					Spec: crdv1alpha1.NetworkPolicyRuleGroupSpec{
						Policy:   "test-egress",
						NodeName: "node5",
						Rules: []crdv1alpha1.NodeRule{
							{
								Action:      "Allow",
								FromAddress: []crdv1alpha1.Address{{IP: "10.10.1.9"}, {IP: "168.1.1.2"}},
								ToAddresses: []crdv1alpha1.Address{{IP: "178.11.1.9"}},
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npc := &NetworkPolicyController{
				clietset:              tt.fields.clietset,
				policyInfomer:         tt.fields.policyInfomer,
				podInformer:           tt.fields.podInformer,
				namespaceInformer:     tt.fields.namespaceInformer,
				endpointsliceInformer: tt.fields.endpointsliceInformer,
				serviceInformer:       tt.fields.serviceInformer,
				clusterGroupInformer:  tt.fields.clusterGroupInformer,
				policyLister:          tt.fields.policyLister,
				podLister:             tt.fields.podLister,
				namespaceLister:       tt.fields.namespaceLister,
				serviceLister:         tt.fields.serviceLister,
				clusterGroupLister:    tt.fields.clusterGroupLister,
				ruleGroupLister:       tt.fields.ruleGroupLister,
				podSynced:             tt.fields.podSynced,
				namepaceSynced:        tt.fields.namepaceSynced,
				clusterPolicySynced:   tt.fields.clusterPolicySynced,
				clusterGroupSynced:    tt.fields.clusterGroupSynced,
				ruleGroupSynced:       tt.fields.ruleGroupSynced,
				queue:                 tt.fields.queue,
				pod2Policy:            tt.fields.pod2Policy,
			}
			got, err := npc.caculatePolicyRulesOnAllNodes(tt.args.cnp)
			if (err != nil) != tt.wantErr {
				t.Errorf("NetworkPolicyController.caculatePolicyAllNodeRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NetworkPolicyController.caculatePolicyAllNodeRules() = %v, want %v", got, tt.want)
			}
		})
	}
}
