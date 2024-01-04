package microseg

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/microseg/types"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	listerv1 "k8s.io/client-go/listers/core/v1"
	dislisterv1 "k8s.io/client-go/listers/discovery/v1"
	dislisterv1beta1 "k8s.io/client-go/listers/discovery/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	podutil "k8s.io/kubernetes/pkg/api/v1/pod"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/clientset/versioned"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/informers/externalversions"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/listers/microsegmentation.security.io/v1alpha1"
)

const maxRetries = 15

type NetworkPolicyController struct {
	clietset              *versioned.Clientset
	policyInfomer         cache.SharedIndexInformer
	podInformer           cache.SharedIndexInformer
	namespaceInformer     cache.SharedIndexInformer
	endpointsliceInformer cache.SharedIndexInformer
	serviceInformer       cache.SharedIndexInformer
	clusterGroupInformer  cache.SharedIndexInformer

	policyLister               v1alpha1.MicrosegClusterNetworkPolicyLister
	podLister                  listerv1.PodLister
	namespaceLister            listerv1.NamespaceLister
	serviceLister              listerv1.ServiceLister
	endpointsliceLister        dislisterv1.EndpointSliceLister
	endpointsliceListerv1beta1 dislisterv1beta1.EndpointSliceLister
	clusterGroupLister         v1alpha1.MicrosegClusterGroupLister
	ruleGroupLister            v1alpha1.NetworkPolicyRuleGroupLister

	podSynced           cache.InformerSynced
	namepaceSynced      cache.InformerSynced
	clusterPolicySynced cache.InformerSynced
	clusterGroupSynced  cache.InformerSynced
	ruleGroupSynced     cache.InformerSynced
	queue               workqueue.RateLimitingInterface
	pod2Policy          map[string]string
}

func podLabelIndexFunc(obj interface{}) ([]string, error) {
	pol := obj.(*crdv1alpha1.MicrosegClusterNetworkPolicy)
	var values []string
	if pol.Spec.PodSelector != nil {
		values = append(values, v1.FormatLabelSelector(pol.Spec.PodSelector))

	}
	for _, in := range pol.Spec.Ingress {
		for _, peer := range in.From {
			if peer.PodSelector != nil {
				values = append(values, v1.FormatLabelSelector(peer.PodSelector))
			}

		}
	}
	for _, in := range pol.Spec.Egress {
		for _, peer := range in.To {
			if peer.PodSelector != nil {
				values = append(values, v1.FormatLabelSelector(peer.PodSelector))
			}
		}
	}
	return values, nil
}

var KeyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc

// getPodPolicyRelationShips select a set of policy keys that matching a given pod
func getPodPolicyRelationShips(policyLister v1alpha1.MicrosegClusterNetworkPolicyLister, namespaceLister listerv1.NamespaceLister, pod *corev1.Pod) (sets.String, error) {
	set := sets.String{}
	policies, err := policyLister.List(labels.Everything())
	if err != nil {
		return nil, err
	}

	matchLabels := func(ls *v1.LabelSelector, policyKey string, labelSet map[string]string) (bool, error) {
		selector, err := v1.LabelSelectorAsSelector(ls)
		if err != nil {
			return false, err
		}
		if selector.Matches(labels.Set(labelSet)) {
			set.Insert(policyKey)
			return true, nil
		}
		return false, nil
	}

	// check wheather a policy is effcted by a pod
	matchFunc := func(podLables *v1.LabelSelector, nsLables *v1.LabelSelector, policyKey string, labelSet map[string]string, podNamespace string) (bool, error) {
		matched, err := matchLabels(podLables, policyKey, labelSet)
		if matched {
			return true, nil
		}
		if err != nil {
			return false, err
		}

		nsSelector, err := v1.LabelSelectorAsSelector(nsLables)
		if err != nil {
			return false, err
		}
		namespaces, err := namespaceLister.List(nsSelector)
		if err != nil {
			return false, err
		}
		for _, ns := range namespaces {
			if ns.Name == podNamespace {
				set.Insert(policyKey)
				return true, nil
			}
		}
		return false, nil
	}

	for _, policy := range policies {
		key, err := KeyFunc(policy)
		if err != nil {
			return nil, err
		}
		matched, err := matchFunc(policy.Spec.PodSelector, policy.Spec.NamespaceSelector, key, labels.Set(pod.Labels), pod.Namespace)
		if matched {
			continue
		}
		if err != nil {
			return nil, err
		}

	INGRESS_FOUND:
		for _, in := range policy.Spec.Ingress {
			for _, peer := range in.From {
				matched, err := matchFunc(peer.PodSelector, peer.NamespaceSelector, key, labels.Set(pod.Labels), pod.Namespace)
				if matched {
					// found = true
					break INGRESS_FOUND
				}
				if err != nil {
					return nil, err
				}
			}
		}
	EGRESS_FOUND:
		for _, out := range policy.Spec.Egress {
			for _, peer := range out.To {
				matched, err := matchFunc(peer.PodSelector, peer.NamespaceSelector, key, labels.Set(pod.Labels), pod.Namespace)
				if matched {
					// found = true
					break EGRESS_FOUND
				}
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return set, nil
}

func getNamespacePolicyRelationShips(policyLister v1alpha1.MicrosegClusterNetworkPolicyLister, namespace *corev1.Namespace) (sets.String, error) {
	set := sets.String{}
	policies, err := policyLister.List(labels.Everything())
	if err != nil {
		return nil, err
	}
	for _, policy := range policies {
		key, err := KeyFunc(policy)
		if err != nil {
			return nil, err
		}
		if policy.Spec.NamespaceSelector != nil {
			selector, err := v1.LabelSelectorAsSelector(policy.Spec.NamespaceSelector)
			if err != nil {
				return nil, err
			}
			if selector.Matches(labels.Set(namespace.Labels)) {
				set.Insert(key)
				continue
			}
		}
	INGRESS_MATCH:
		for _, in := range policy.Spec.Ingress {
			for _, peer := range in.From {
				if peer.NamespaceSelector != nil {
					selector, err := v1.LabelSelectorAsSelector(peer.NamespaceSelector)
					if err != nil {
						return nil, err
					}
					if selector.Matches(labels.Set(namespace.Labels)) {
						set.Insert(key)
						break INGRESS_MATCH
					}
				}
			}
		}
	ENGRESS_MATCH:
		for _, out := range policy.Spec.Egress {
			for _, peer := range out.To {
				selector, err := v1.LabelSelectorAsSelector(peer.NamespaceSelector)
				if err != nil {
					return nil, err
				}
				if selector.Matches(labels.Set(namespace.Labels)) {
					set.Insert(key)
					break ENGRESS_MATCH
				}
			}
		}
	}
	return set, nil
}

func getClusterGroupPolicyRelationShips(policyLister v1alpha1.MicrosegClusterNetworkPolicyLister, clusterGrop *crdv1alpha1.MicrosegClusterGroup) (sets.String, error) {
	set := sets.String{}
	policies, err := policyLister.List(labels.Everything())
	if err != nil {
		return nil, err
	}
	for _, policy := range policies {
		key, err := KeyFunc(policy)
		if err != nil {
			return nil, err
		}
		if policy.Spec.Group == clusterGrop.Name {
			set.Insert(key)
			continue
		}

	INGRESS_MATCH:
		for _, in := range policy.Spec.Ingress {
			for _, peer := range in.From {
				if peer.Group == clusterGrop.Name {
					set.Insert(key)
					break INGRESS_MATCH
				}
			}
		}

	EGRESS_MATCH:
		for _, out := range policy.Spec.Egress {
			for _, peer := range out.To {
				if peer.Group == clusterGrop.Name {
					set.Insert(key)
					break EGRESS_MATCH
				}
			}
		}
	}
	return set, nil
}

func (npc *NetworkPolicyController) addPod(obj interface{}) {
	pod := obj.(*corev1.Pod)
	if pod.Status.PodIP == "" || pod.Spec.HostNetwork {
		return
	}
	logging.Get().Debug().Msgf("add pod %s/%s", pod.Namespace, pod.Name)
	policies, err := getPodPolicyRelationShips(npc.policyLister, npc.namespaceLister, pod)
	if err != nil {
		logging.Get().Err(err).Msgf("process add pod event err")
		return
	}
	for key := range policies {
		npc.queue.Add(key)
	}
}

func (npc *NetworkPolicyController) updatePod(oldObj, newObject interface{}) {
	oldPod := oldObj.(*corev1.Pod)
	newPod := newObject.(*corev1.Pod)
	if oldPod.Status.PodIP == newPod.Status.PodIP || newPod.Spec.HostNetwork {
		return
	}
	logging.Get().Debug().Msgf("update pod %s", oldPod.Name)
	policies, err := getPodPolicyRelationShips(npc.policyLister, npc.namespaceLister, newPod)
	if err != nil {
		logging.Get().Err(err).Msgf("process add pod event err")
		return
	}
	for key := range policies {
		npc.queue.Add(key)
	}
}

func GetResourceFromDeleteAction[T corev1.Pod | crdv1alpha1.MicrosegClusterGroup](obj interface{}) *T {
	if pod, ok := obj.(*T); ok {
		// Enqueue all the services that the pod used to be a member of.
		// This is the same thing we do when we add a pod.
		return pod
	}
	// If we reached here it means the pod was deleted but its final state is unrecorded.
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		// utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
		return nil
	}
	pod, ok := tombstone.Obj.(*T)
	if !ok {
		// utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a Pod: %#v", obj))
		return nil
	}
	return pod
}

func (npc *NetworkPolicyController) deletePod(obj interface{}) {
	pod := GetResourceFromDeleteAction[corev1.Pod](obj)
	if pod.Spec.HostNetwork {
		return
	}
	if pod != nil {
		logging.Get().Debug().Msgf("delete pod %s/%s", pod.Namespace, pod.Name)
		npc.addPod(pod)
	}
}

func (npc *NetworkPolicyController) addClusterPolicy(obj interface{}) {
	cnp := obj.(*crdv1alpha1.MicrosegClusterNetworkPolicy)
	logging.Get().Debug().Msgf("add cluster policy %s", cnp.Name)
	key, err := KeyFunc(cnp)
	if err != nil {
		return
	}
	npc.queue.Add(key)
}

func (npc *NetworkPolicyController) updateClusterPolicy(oldObj, newObject interface{}) {
	oldPolicy := oldObj.(*crdv1alpha1.MicrosegClusterNetworkPolicy)
	newPolicy := newObject.(*crdv1alpha1.MicrosegClusterNetworkPolicy)

	logging.Get().Debug().Msgf("update cluster policy %s", oldPolicy.Name)
	key, err := KeyFunc(newPolicy)
	if err != nil {
		return
	}
	npc.queue.Add(key)
}

func (npc *NetworkPolicyController) deleteClusterPolicy(obj interface{}) {
	policy := obj.(*crdv1alpha1.MicrosegClusterNetworkPolicy)
	logging.Get().Debug().Msgf("delete cluster policy %s", policy.Name)
	key, err := KeyFunc(policy)
	if err != nil {
		return
	}
	npc.queue.Add(key)
}

func (npc *NetworkPolicyController) addClusterGroup(obj interface{}) {
	cg := obj.(*crdv1alpha1.MicrosegClusterGroup)

	policies, err := getClusterGroupPolicyRelationShips(npc.policyLister, cg)
	if err != nil {
		return
	}
	for key := range policies {
		npc.queue.Add(key)
	}
}

func (npc *NetworkPolicyController) updateClusterGroup(oldObj, newObj interface{}) {
	oldGroup := oldObj.(*crdv1alpha1.MicrosegClusterGroup)
	newGroup := newObj.(*crdv1alpha1.MicrosegClusterGroup)
	if oldGroup.ResourceVersion == newGroup.ResourceVersion {
		return
	}
	if reflect.DeepEqual(oldGroup.Spec, newGroup.Spec) {
		return
	}
	policies, err := getClusterGroupPolicyRelationShips(npc.policyLister, newGroup)
	if err != nil {
		return
	}
	for key := range policies {
		npc.queue.Add(key)
	}
}

func (npc *NetworkPolicyController) deleteClusterGroup(obj interface{}) {
	clusterGroup := GetResourceFromDeleteAction[crdv1alpha1.MicrosegClusterGroup](obj)
	if clusterGroup != nil {
		logging.Get().Debug().Msgf("delete ClusterGroup %s", clusterGroup.Name)
		npc.addClusterGroup(clusterGroup)
	}
}

func (npc *NetworkPolicyController) addNamespace(obj interface{}) {
	namespace := obj.(*corev1.Namespace)
	policies, err := getNamespacePolicyRelationShips(npc.policyLister, namespace)
	if err != nil {
		return
	}
	for key := range policies {
		npc.queue.Add(key)
	}
}

func (npc *NetworkPolicyController) updateNamespace(oldObj, newObj interface{}) {
	oldNamespace := oldObj.(*corev1.Namespace)
	newNamespace := newObj.(*corev1.Namespace)

	// Periodic resync will send update events for all known pods.
	if oldNamespace.ResourceVersion == newNamespace.ResourceVersion {
		return
	}

	if reflect.DeepEqual(oldNamespace.Labels, newNamespace.Labels) {
		return
	}

	policies, err := getNamespacePolicyRelationShips(npc.policyLister, newNamespace)
	if err != nil {
		return
	}
	for key := range policies {
		npc.queue.Add(key)
	}
}

func (npc *NetworkPolicyController) deleteNamespace(obj interface{}) {
	// do nothing here, because pods in this namespace have been deleted
}

func (npc *NetworkPolicyController) addService(obj interface{}) {
	service := obj.(*corev1.Service)

	esLabelSelector := labels.Set(map[string]string{
		"kubernetes.io/service-name":             service.Name,
		"endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
	}).AsSelectorPreValidated()

	var podNamespace, podName string
	if npc.endpointsliceLister != nil {
		endpointSlices, err := npc.endpointsliceLister.EndpointSlices(service.Namespace).List(esLabelSelector)
		if err != nil {
			return
		}

		if len(endpointSlices) == 0 {
			return
		}
		for _, ep := range endpointSlices[0].Endpoints {
			if ep.TargetRef.Kind == "Pod" {
				podNamespace, podName = ep.TargetRef.Namespace, ep.TargetRef.Name
			}
		}
	} else {
		endpointSlices, err := npc.endpointsliceListerv1beta1.EndpointSlices(service.Namespace).List(esLabelSelector)
		if err != nil {
			return
		}

		if len(endpointSlices) == 0 {
			return
		}
		for _, ep := range endpointSlices[0].Endpoints {
			if ep.TargetRef.Kind == "Pod" {
				podNamespace, podName = ep.TargetRef.Namespace, ep.TargetRef.Name
			}
		}
	}
	pod, err := npc.podLister.Pods(podNamespace).Get(podName)
	if err != nil {
		return
	}
	npc.addPod(pod)
}

func (npc *NetworkPolicyController) updateService(oldObj, newObj interface{}) {
	newSvc := newObj.(*corev1.Service)
	oldSvc := oldObj.(*corev1.Service)
	if reflect.DeepEqual(newSvc.Spec, oldSvc.Spec) {
		return
	}
	npc.addService(newSvc)
}

func (npc *NetworkPolicyController) deleteService(obj interface{}) {
}

func NewNetworkPolicyController(clientset *versioned.Clientset, factory informers.SharedInformerFactory, crdFactory externalversions.SharedInformerFactory) *NetworkPolicyController {
	policyInfomer := crdFactory.Microsegmentation().V1alpha1().MicrosegClusterNetworkPolicies().Informer()

	controller := NetworkPolicyController{
		clietset:             clientset,
		policyInfomer:        policyInfomer,
		clusterGroupInformer: crdFactory.Microsegmentation().V1alpha1().MicrosegClusterGroups().Informer(),
		podInformer:          factory.Core().V1().Pods().Informer(),
		namespaceInformer:    factory.Core().V1().Namespaces().Informer(),
		serviceInformer:      factory.Core().V1().Services().Informer(),
		serviceLister:        factory.Core().V1().Services().Lister(),
		policyLister:         crdFactory.Microsegmentation().V1alpha1().MicrosegClusterNetworkPolicies().Lister(),
		clusterGroupLister:   crdFactory.Microsegmentation().V1alpha1().MicrosegClusterGroups().Lister(),
		ruleGroupLister:      crdFactory.Microsegmentation().V1alpha1().NetworkPolicyRuleGroups().Lister(),
		podLister:            factory.Core().V1().Pods().Lister(),
		namespaceLister:      factory.Core().V1().Namespaces().Lister(),
		podSynced:            factory.Core().V1().Pods().Informer().HasSynced,
		namepaceSynced:       factory.Core().V1().Namespaces().Informer().HasSynced,
		clusterPolicySynced:  crdFactory.Microsegmentation().V1alpha1().MicrosegClusterNetworkPolicies().Informer().HasSynced,
		clusterGroupSynced:   crdFactory.Microsegmentation().V1alpha1().MicrosegClusterGroups().Informer().HasSynced,
		ruleGroupSynced:      crdFactory.Microsegmentation().V1alpha1().NetworkPolicyRuleGroups().Informer().HasSynced,
		queue:                workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "networkpolicy-queue"),
		pod2Policy:           make(map[string]string, 100),
	}

	policyInfomer.AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.addClusterPolicy,
		UpdateFunc: controller.updateClusterPolicy,
		DeleteFunc: controller.deleteClusterPolicy,
	}, time.Hour*8)

	ver, err := clientset.DiscoveryClient.ServerVersion()
	if err != nil {
		logging.Get().Err(err).Msg("faild to get kubenetes version")
		return nil
	}
	v := k8s.GetKubeMininorVersion(ver.String())
	if v < 21 {
		controller.endpointsliceListerv1beta1 = factory.Discovery().V1beta1().EndpointSlices().Lister()
	} else {
		controller.endpointsliceLister = factory.Discovery().V1().EndpointSlices().Lister()
	}

	policyInfomer.AddIndexers(cache.Indexers{"pod-label-index": podLabelIndexFunc})

	// controller.endpointsliceInformer.AddIndexers(cache.Indexers{"pod-name-index": func(obj interface{}) ([]string, error) {
	// 	eps := obj.(*discovery1.EndpointSlice)
	// 	var values []string
	// 	for _, e := range eps.Endpoints {
	// 		if e.TargetRef.Kind == "Pod" {
	// 			values = append(values, fmt.Sprintf("%s/%s", e.TargetRef.Namespace, e.TargetRef.Name))
	// 		}
	// 	}
	// 	return values, nil
	// }})

	controller.clusterGroupInformer.AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.addClusterGroup,
		UpdateFunc: controller.updateClusterGroup,
		DeleteFunc: controller.deleteClusterGroup,
	}, time.Hour*8)

	controller.podInformer.AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.addPod,
		UpdateFunc: controller.updatePod,
		DeleteFunc: controller.deletePod,
	}, time.Hour*8)

	controller.namespaceInformer.AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.addNamespace,
		UpdateFunc: controller.updateNamespace,
		DeleteFunc: controller.deleteNamespace,
	}, time.Hour*8)

	controller.serviceInformer.AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.addService,
		UpdateFunc: controller.updateService,
		DeleteFunc: controller.deleteService,
	}, time.Hour*8)

	// controller.endpointsliceInformer.AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
	// 	AddFunc:    controller.addService,
	// 	UpdateFunc: controller.updateService,
	// 	DeleteFunc: controller.deleteService,
	// }, time.Hour*8)
	return &controller
}

func (npc *NetworkPolicyController) Run(stopChan chan struct{}) {
	logging.Get().Info().Msg("run Network Policy Controller")
	if !cache.WaitForNamedCacheSync("network_policy", stopChan,
		npc.podSynced, npc.namepaceSynced, npc.clusterPolicySynced, npc.clusterGroupSynced, npc.ruleGroupSynced) {
		return
	}
	wait.Until(npc.worker, time.Second, stopChan)
}

func (npc *NetworkPolicyController) worker() {
	logging.Get().Info().Msg("start worker")
	for npc.processNextItem() {
	}
}

func (npc *NetworkPolicyController) syncRules(rules map[string]*crdv1alpha1.NetworkPolicyRuleGroup) error {
	for _, r := range rules {
		curRule, err := npc.ruleGroupLister.Get(r.Name)
		if err != nil {
			if errors.IsNotFound(err) {
				_, err = npc.clietset.MicrosegmentationV1alpha1().NetworkPolicyRuleGroups().Create(context.TODO(), r, v1.CreateOptions{})
				if err != nil {
					return err
				}
				continue
			}
			return err
		}
		newRule := curRule.DeepCopy()
		newRule.Spec = r.Spec
		_, err = npc.clietset.MicrosegmentationV1alpha1().NetworkPolicyRuleGroups().Update(context.TODO(), newRule, v1.UpdateOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}
func (npc *NetworkPolicyController) syncPolicy(key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if namespace == "" {
		cnp, err := npc.policyLister.Get(name)
		if err != nil {
			if !errors.IsNotFound(err) {
				return err
			}
			logging.Get().Info().Msgf("policy : %s has bedd removed", key)
			return nil
		}
		internalPolicy, err := npc.caculatePolicy(cnp)
		if err != nil {
			return err
		}
		logging.Get().Info().Msgf("generated policy: %v", internalPolicy)

		// rules, err := npc.caculatePolicyNodeRules(cnp)
		rules, err := npc.caculatePolicyRulesOnAllNodes(cnp)
		if err != nil {
			return err
		}
		data, _ := json.Marshal(rules)
		logging.Get().Info().Msgf("generated policy group: %v", string(data))
		err = npc.syncRules(rules)
		if err != nil {
			logging.Get().Err(err).Msgf("failed to sync node rules")
			return err
		}
	}

	return nil
}
func (npc *NetworkPolicyController) processNextItem() bool {
	key, quit := npc.queue.Get()
	if quit {
		return false
	}
	defer npc.queue.Done(key)

	err := npc.syncPolicy(key.(string))
	npc.handleErr(err, key)

	return true
}

func (npc *NetworkPolicyController) handleErr(err error, key interface{}) {
	if err == nil {
		npc.queue.Forget(key)
		return
	}

	ns, name, keyErr := cache.SplitMetaNamespaceKey(key.(string))
	if keyErr != nil {
		logging.Get().Err(err).Msgf("Failed to split meta namespace cache key %s", key)
	}

	if npc.queue.NumRequeues(key) < maxRetries {
		klog.V(2).InfoS("Error syncing policy, retrying", "service", klog.KRef(ns, name), "err", err)
		npc.queue.AddRateLimited(key)
		return
	}

	logging.Get().Warn().Msgf("Dropping service %q out of the queue: %v", key, err)
	npc.queue.Forget(key)
	// utilruntime.HandleError(err)
}

func (npc *NetworkPolicyController) caculatePolicy(cnp *crdv1alpha1.MicrosegClusterNetworkPolicy) (*types.NetwokPolicy, error) {
	var networkpolicy types.NetwokPolicy
	appliedAddresses, err := npc.caculateAddress(cnp.Spec.PodSelector, cnp.Spec.NamespaceSelector, cnp.Spec.Group)
	if err != nil {
		return nil, err
	}
	networkpolicy.AppliedAddress = appliedAddresses

	// caculate ingress addresses
	var fromRules []types.NetwokPolicyRule
	for _, r := range cnp.Spec.Ingress {
		rule := types.NetwokPolicyRule{}
		for _, peer := range r.From {
			address, err := npc.caculateAddress(peer.PodSelector, peer.NamespaceSelector, peer.Group)
			if err != nil {
				return nil, err
			}
			rule.FromAddress = append(rule.FromAddress, address...)
		}
		fromRules = append(fromRules, rule)
	}
	networkpolicy.Rules = append(networkpolicy.Rules, fromRules...)

	// caculate egress addresses
	var toRules []types.NetwokPolicyRule
	for _, r := range cnp.Spec.Egress {
		rule := types.NetwokPolicyRule{}
		for _, peer := range r.To {
			address, err := npc.caculateAddress(peer.PodSelector, peer.NamespaceSelector, peer.Group)
			if err != nil {
				return nil, err
			}
			rule.ToAddresses = append(rule.ToAddresses, address...)
		}
		toRules = append(toRules, rule)
	}
	networkpolicy.Rules = append(networkpolicy.Rules, toRules...)
	return &networkpolicy, nil
}

// caculatePodsBylabelSelector match all pods by label selectors
func (npc *NetworkPolicyController) caculatePodsBylabelSelector(podLabels *v1.LabelSelector, namespaceLabels *v1.LabelSelector) ([]*corev1.Pod, error) {
	var pods []*corev1.Pod
	var err error

	if namespaceLabels != nil {
		selector, _ := v1.LabelSelectorAsSelector(namespaceLabels)
		namespaces, err := npc.namespaceLister.List(selector)
		if err != nil {
			return nil, err
		}

		if podLabels != nil {
			// Pods are matched from Namespaces matched by the NamespaceSelector.
			selector, _ := v1.LabelSelectorAsSelector(podLabels)
			for _, ns := range namespaces {
				podLister := npc.podLister.Pods(ns.Name)
				ps, err := podLister.List(selector)
				if err != nil {
					return nil, err
				}
				pods = append(pods, ps...)
			}
		} else {
			for _, ns := range namespaces {
				podLister := npc.podLister.Pods(ns.Name)
				ps, err := podLister.List(labels.Everything())
				if err != nil {
					return nil, err
				}
				pods = append(pods, ps...)
			}
		}
		return pods, nil
	}

	if podLabels != nil {
		selector, _ := v1.LabelSelectorAsSelector(podLabels)
		pods, err = npc.podLister.List(selector)
		if err != nil {
			return nil, err
		}
	}

	uniqPods := make([]*corev1.Pod, 0, len(pods))
	for _, p := range pods {
		if !p.Spec.HostNetwork {
			uniqPods = append(uniqPods, p)
		}

	}
	return uniqPods, nil
}

func (npc *NetworkPolicyController) caculateRelatedPods(podLabels *v1.LabelSelector, namespaceLabels *v1.LabelSelector, group string) ([]*corev1.Pod, error) {
	pods, err := npc.caculatePodsBylabelSelector(podLabels, namespaceLabels)
	if err != nil {
		return nil, err
	}
	if group != "" {
		clusterGroup, err := npc.clusterGroupLister.Get(group)
		if err != nil {
			return nil, err
		}
		groupPods, err := npc.caculatePodsBylabelSelector(clusterGroup.Spec.PodSelector, clusterGroup.Spec.NamespaceSelector)
		if err != nil {
			return nil, err
		}
		pods = podsUnion(pods, groupPods)
	}
	return pods, err
}

func podReference(pod *corev1.Pod) *crdv1alpha1.EntityReference {
	return &crdv1alpha1.EntityReference{Namespace: pod.Namespace, Name: pod.Name}
}

// caculateAddress caculate a list of pod ips from labels
func (npc *NetworkPolicyController) caculateAddress(podLabels *v1.LabelSelector, namespaceLabels *v1.LabelSelector, group string) ([]crdv1alpha1.Address, error) {
	pods, err := npc.caculateRelatedPods(podLabels, namespaceLabels, group)
	if err != nil {
		return nil, err
	}
	var appliedAddresses []crdv1alpha1.Address
	for _, pod := range pods {
		appliedAddresses = append(appliedAddresses, crdv1alpha1.Address{
			IP:           pod.Status.PodIP,
			PodReference: podReference(pod),
		})
	}

	AddressSlice(appliedAddresses).Sort()
	return appliedAddresses, nil
}

// caculateAddress caculate a list of pod ips from labels
func (npc *NetworkPolicyController) caculateAddressMap(podLabels *v1.LabelSelector, namespaceLabels *v1.LabelSelector, group string) (map[string][]crdv1alpha1.Address, error) {
	pods, err := npc.caculateRelatedPods(podLabels, namespaceLabels, group)
	if err != nil {
		return nil, err
	}
	addresseMap := make(map[string][]crdv1alpha1.Address)
	for _, pod := range pods {
		logging.Get().Info().Msgf("pod ip: %s in node %s", pod.Status.PodIP, pod.Spec.NodeName)
		if pod.Status.PodIP != "" && pod.Spec.NodeName != "" {
			addresseMap[pod.Spec.NodeName] = append(addresseMap[pod.Spec.NodeName], crdv1alpha1.Address{
				IP:           pod.Status.PodIP,
				PodReference: podReference(pod),
			})
		}
	}

	// sort.StringSlice(appliedAddresses).Sort()
	return addresseMap, nil
}

func (npc *NetworkPolicyController) caculateNodeRules(cnp *crdv1alpha1.MicrosegClusterNetworkPolicy) (map[string][]types.NodeRule, error) {
	rules := make(map[string][]types.NodeRule)
	addressesMap, err := npc.caculateAddressMap(cnp.Spec.PodSelector, cnp.Spec.NamespaceSelector, cnp.Spec.Group)
	if err != nil {
		return nil, err
	}
	if len(addressesMap) == 0 {
		logging.Get().Warn().Msg("empty node-address map!")
		return rules, nil
	}
	for _, r := range cnp.Spec.Ingress {
		for _, peer := range r.From {
			adddress, err := npc.caculateAddress(peer.PodSelector, peer.NamespaceSelector, peer.Group)
			if err != nil {
				return nil, err
			}
			if len(adddress) == 0 {
				continue
			}
			for node, ads := range addressesMap {
				rules[node] = append(rules[node], types.NodeRule{
					PolicyName:  cnp.Name,
					NodeName:    node,
					Priority:    cnp.Spec.Priority,
					Protocol:    r.Protocol,
					Action:      string(*r.Action),
					Ports:       r.Ports,
					FromAddress: adddress,
					ToAddresses: ads,
				})
			}
		}
	}

	fromAddress := AddressMaptoSlice(addressesMap)
	for _, r := range cnp.Spec.Egress {
		for _, peer := range r.To {
			toAddrMap, err := npc.caculateAddressMap(peer.PodSelector, peer.NamespaceSelector, peer.Group)
			if err != nil {
				return nil, err
			}
			for node, ads := range toAddrMap {
				rules[node] = append(rules[node], types.NodeRule{
					PolicyName:  cnp.Name,
					NodeName:    node,
					Priority:    cnp.Spec.Priority,
					Protocol:    r.Protocol,
					Action:      string(*r.Action),
					Ports:       r.Ports,
					ToAddresses: ads,
					FromAddress: fromAddress,
				})
			}
		}
	}

	return rules, nil
}

func (npc *NetworkPolicyController) caculatePolicyNodeRules1(cnp *crdv1alpha1.MicrosegClusterNetworkPolicy) (map[string]*crdv1alpha1.NetworkPolicyRuleGroup, error) {
	rules := map[string]*crdv1alpha1.NetworkPolicyRuleGroup{}
	addressesMap, err := npc.caculateAddressMap(cnp.Spec.PodSelector, cnp.Spec.NamespaceSelector, cnp.Spec.Group)
	if err != nil {
		return nil, err
	}
	if len(addressesMap) == 0 {
		logging.Get().Warn().Msg("empty node-address map!")
		return rules, nil
	}

	generateCRDPolicyRule := func(policy, nodeName string) {
		if _, ok := rules[nodeName]; !ok {
			ownerRef := v1.NewControllerRef(cnp, schema.GroupVersionKind{Group: "microsegmentation.security.io", Version: "v1alpha1", Kind: "MicrosegClusterNetworkPolicy"})
			rules[nodeName] = &crdv1alpha1.NetworkPolicyRuleGroup{
				ObjectMeta: v1.ObjectMeta{
					Name: fmt.Sprintf("%s-%s", cnp.Name, nodeName),
					Labels: map[string]string{
						"kubernetes.io/networkpolicy-name": cnp.Name,
						"kubernetes.io/node-name":          nodeName,
					},
					OwnerReferences: []v1.OwnerReference{*ownerRef},
				},
				Spec: crdv1alpha1.NetworkPolicyRuleGroupSpec{
					Policy:   cnp.Name,
					NodeName: nodeName,
				},
			}
		}
	}

	for _, r := range cnp.Spec.Ingress {
		for _, peer := range r.From {
			adddress, err := npc.caculateAddress(peer.PodSelector, peer.NamespaceSelector, peer.Group)
			if err != nil {
				return nil, err
			}
			if len(adddress) == 0 && peer.IPBlock == nil {
				logging.Get().Info().Msg("empty address")
				continue
			}

			for node, ads := range addressesMap {
				generateCRDPolicyRule(cnp.Name, node)
				rules[node].Spec.Rules = append(rules[node].Spec.Rules, crdv1alpha1.NodeRule{
					Priority:    cnp.Spec.Priority,
					Protocol:    r.Protocol,
					Action:      string(*r.Action),
					Ports:       r.Ports,
					ToAddresses: ads,
					FromAddress: adddress,
					FromIPBlock: peer.IPBlock,
					Http:        peer.Http,
				})
			}
		}
	}

	fromAddress := AddressMaptoSlice(addressesMap)
	for _, r := range cnp.Spec.Egress {
		for _, peer := range r.To {
			if peer.IPBlock != nil {
				for node, ads := range addressesMap {
					generateCRDPolicyRule(cnp.Name, node)
					rules[node].Spec.Rules = append(rules[node].Spec.Rules, crdv1alpha1.NodeRule{
						Priority:    cnp.Spec.Priority,
						Protocol:    r.Protocol,
						Action:      string(*r.Action),
						Ports:       r.Ports,
						FromAddress: ads,
						ToIPBlock:   peer.IPBlock,
						Http:        peer.Http,
					})
				}
				continue
			}

			toAddrMap, err := npc.caculateAddressMap(peer.PodSelector, peer.NamespaceSelector, peer.Group)
			if err != nil {
				return nil, err
			}

			for node, ads := range toAddrMap {
				generateCRDPolicyRule(cnp.Name, node)
				rules[node].Spec.Rules = append(rules[node].Spec.Rules, crdv1alpha1.NodeRule{
					Priority:    cnp.Spec.Priority,
					Protocol:    r.Protocol,
					Action:      string(*r.Action),
					Ports:       r.Ports,
					ToAddresses: ads,
					FromAddress: fromAddress,
				})
			}
		}
	}

	return rules, nil
}

type endPoint struct {
	Address string
	Ports   []crdv1alpha1.NetworkPolicyPort
}

func getServicePort(pod *corev1.Pod, svc *corev1.Service, policyPorts []crdv1alpha1.NetworkPolicyPort) []crdv1alpha1.NetworkPolicyPort {
	ports := []crdv1alpha1.NetworkPolicyPort{}

	isPortIn := func(targetPort int, policyPort *crdv1alpha1.NetworkPolicyPort) bool {
		if policyPort.EndPort != nil {
			if targetPort >= int(policyPort.Port.IntVal) && targetPort <= int(*policyPort.EndPort) {
				return true
			}
			return false
		}
		if targetPort == int(policyPort.Port.IntVal) {
			return true
		}
		return false
	}
	for _, svcPort := range svc.Spec.Ports {
		targetPort, err := podutil.FindPort(pod, &svcPort)
		if err != nil {
			logging.Get().Info().Msgf("Failed to find port for service: %s/%s: %v", svc.Namespace, svc.Name, err)
			continue
		}

		svcProtocol := svcPort.Protocol
		if svcProtocol == "" {
			svcProtocol = corev1.ProtocolTCP
		}
		if len(policyPorts) == 0 {
			port := intstr.FromInt(int(svcPort.Port))
			ports = append(ports, crdv1alpha1.NetworkPolicyPort{
				Protocol: &svcProtocol,
				Port:     &port,
			})
		}
		for _, pp := range policyPorts {
			protocol := corev1.ProtocolTCP
			if pp.Protocol != nil {
				protocol = *pp.Protocol
			}
			// if policy port unset, match all ports.
			if (isPortIn(targetPort, &pp)) && svcProtocol == protocol {
				port := intstr.FromInt(int(svcPort.Port))
				ports = append(ports, crdv1alpha1.NetworkPolicyPort{
					Protocol: &protocol,
					Port:     &port,
				})
				break
			}
		}
	}
	return ports
}

func (npc *NetworkPolicyController) getRelatedServiceAddr(podLabels *v1.LabelSelector, namespaceLabels *v1.LabelSelector, group string, policyPorts []crdv1alpha1.NetworkPolicyPort) ([]endPoint, error) {
	pods, err := npc.caculateRelatedPods(podLabels, namespaceLabels, group)
	if err != nil {
		return nil, err
	}
	pods = dedupPods(pods)
	svcMap := make(map[string]struct{})
	set := []endPoint{}
	for _, pod := range pods {
		services, err := npc.serviceLister.Services(pod.Namespace).List(labels.Everything())
		if err != nil {
			return nil, err
		}
		logging.Get().Info().Msgf("matching service by pod: %s/%s", pod.Namespace, pod.Name)

		for _, service := range services {
			if service.Spec.Selector == nil {
				// if the service has a nil selector this means selectors match nothing, not everything.
				continue
			}
			logging.Get().Info().Msgf("matching service:1 %s/%s", service.Namespace, service.Name)

			l, err := labels.ValidatedSelectorFromSet(service.Spec.Selector)
			if err != nil {
				return nil, err
			}

			if l.Matches(labels.Set(pod.Labels)) {
				logging.Get().Info().Msgf("matching service2: %s/%s", service.Namespace, service.Name)

				key, _ := KeyFunc(service)
				if _, exist := svcMap[key]; exist {
					continue
				} else {
					svcMap[key] = struct{}{}
				}

				if service.Spec.ClusterIP == "" || service.Spec.ClusterIP == "None" {
					continue
				}

				ports := getServicePort(pod, service, policyPorts)
				if len(ports) > 0 {
					logging.Get().Info().Msgf("matching service port %s", service.Spec.ClusterIP)
					set = append(set, endPoint{
						Address: service.Spec.ClusterIP,
						Ports:   ports,
					})
				}
			}
		}
	}
	data, _ := json.Marshal(set)
	logging.Get().Info().Msgf("generated service addr: %s", data)
	return set, nil
}

func (npc *NetworkPolicyController) caculatePolicyNodeRules(cnp *crdv1alpha1.MicrosegClusterNetworkPolicy) (map[string]*crdv1alpha1.NetworkPolicyRuleGroup, error) {
	rules := map[string]*crdv1alpha1.NetworkPolicyRuleGroup{}
	addressesMap, err := npc.caculateAddressMap(cnp.Spec.PodSelector, cnp.Spec.NamespaceSelector, cnp.Spec.Group)
	if err != nil {
		return nil, err
	}
	if len(addressesMap) == 0 {
		logging.Get().Warn().Msg("empty node-address map!")
		return rules, nil
	}

	generateCRDPolicyRule := func(cnp *crdv1alpha1.MicrosegClusterNetworkPolicy, rule *crdv1alpha1.Rule, addressMap map[string][]crdv1alpha1.Address,
		addresses []crdv1alpha1.Address, ipBlock *crdv1alpha1.IPBlock, direction string) {
		for node, ads := range addressesMap {
			if _, ok := rules[node]; !ok {
				ownerRef := v1.NewControllerRef(cnp, schema.GroupVersionKind{Group: "microsegmentation.security.io", Version: "v1alpha1", Kind: "MicrosegClusterNetworkPolicy"})
				rules[node] = &crdv1alpha1.NetworkPolicyRuleGroup{
					ObjectMeta: v1.ObjectMeta{
						Name: fmt.Sprintf("%s-%s", cnp.Name, node),
						Labels: map[string]string{
							"kubernetes.io/networkpolicy-name": cnp.Name,
							"kubernetes.io/node-name":          node,
						},
						OwnerReferences: []v1.OwnerReference{*ownerRef},
					},
					Spec: crdv1alpha1.NetworkPolicyRuleGroupSpec{
						Policy:   cnp.Name,
						NodeName: node,
					},
				}
			}
			switch direction {
			case "ingress":
				rules[node].Spec.Rules = append(rules[node].Spec.Rules, crdv1alpha1.NodeRule{
					Direction:   "ingress",
					Priority:    cnp.Spec.Priority,
					Protocol:    rule.Protocol,
					Action:      string(*rule.Action),
					Ports:       rule.Ports,
					ToAddresses: ads,
					FromAddress: addresses,
					FromIPBlock: ipBlock,
				})
			case "egress":
				rules[node].Spec.Rules = append(rules[node].Spec.Rules, crdv1alpha1.NodeRule{
					Direction:   "egress",
					Priority:    cnp.Spec.Priority,
					Protocol:    rule.Protocol,
					Action:      string(*rule.Action),
					Ports:       rule.Ports,
					ToAddresses: addresses,
					FromAddress: ads,
					ToIPBlock:   ipBlock,
				})
			default:
				logging.Get().Error().Msgf("invalid rule direction %s ", direction)
			}
		}
	}

	for _, r := range cnp.Spec.Ingress {
		if len(r.From) == 0 {
			generateCRDPolicyRule(cnp, &r, addressesMap, []crdv1alpha1.Address{{IP: "0.0.0.0"}}, nil, "ingress")
		}
		for _, peer := range r.From {
			var adddress []crdv1alpha1.Address
			if peer.PodSelector == nil && peer.NamespaceSelector == nil && peer.Group == "" && peer.IPBlock == nil {
				adddress = append(adddress, crdv1alpha1.Address{IP: "0.0.0.0"})
			} else {
				adddress, err = npc.caculateAddress(peer.PodSelector, peer.NamespaceSelector, peer.Group)
				if err != nil {
					return nil, err
				}
			}
			if len(adddress) == 0 && peer.IPBlock == nil {
				logging.Get().Info().Msg("empty address inside egress rules")
				continue
			}
			generateCRDPolicyRule(cnp, &r, addressesMap, adddress, peer.IPBlock, "ingress")
		}
	}

	for _, r := range cnp.Spec.Egress {
		if len(r.To) == 0 {
			generateCRDPolicyRule(cnp, &r, addressesMap, []crdv1alpha1.Address{{IP: "0.0.0.0"}}, nil, "egress")
		}
		for _, peer := range r.To {
			var toAddresses []crdv1alpha1.Address
			var endpoints []endPoint
			if peer.PodSelector == nil && peer.NamespaceSelector == nil && peer.Group == "" && peer.IPBlock == nil {
				toAddresses = []crdv1alpha1.Address{{IP: "0.0.0.0"}}
			} else {
				endpoints, err = npc.getRelatedServiceAddr(peer.PodSelector, peer.NamespaceSelector, peer.Group, r.Ports)
				if err != nil {
					return nil, err
				}

				toAddresses, err = npc.caculateAddress(peer.PodSelector, peer.NamespaceSelector, peer.Group)
				if err != nil {
					return nil, err
				}
			}

			if len(toAddresses) == 0 && peer.IPBlock == nil && len(endpoints) == 0 {
				logging.Get().Info().Msg("empty address in egress rules")
				continue
			}

			// for egress rule
			generateCRDPolicyRule(cnp, &r, addressesMap, toAddresses, peer.IPBlock, "egress")
			for node, ads := range addressesMap {
				for _, ep := range endpoints {
					rules[node].Spec.Rules = append(rules[node].Spec.Rules, crdv1alpha1.NodeRule{
						Direction:   "egress",
						Priority:    cnp.Spec.Priority,
						Protocol:    r.Protocol,
						Action:      string(*r.Action),
						Ports:       ep.Ports,
						ToAddresses: []crdv1alpha1.Address{{IP: ep.Address}},
						FromAddress: ads,
					})
				}
			}
		}
	}
	return rules, nil
}

func generateCRDPolicyRule(cnp *crdv1alpha1.MicrosegClusterNetworkPolicy, rule *crdv1alpha1.Rule, addressMap map[string][]crdv1alpha1.Address,
	addresses []crdv1alpha1.Address, ipBlock *crdv1alpha1.IPBlock, http *crdv1alpha1.Http, direction string) map[string]*crdv1alpha1.NetworkPolicyRuleGroup {
	rules := map[string]*crdv1alpha1.NetworkPolicyRuleGroup{}
	for node, ads := range addressMap {
		if _, ok := rules[node]; !ok {
			ownerRef := v1.NewControllerRef(cnp, schema.GroupVersionKind{Group: "microsegmentation.security.io", Version: "v1alpha1", Kind: "MicrosegClusterNetworkPolicy"})
			rules[node] = &crdv1alpha1.NetworkPolicyRuleGroup{
				ObjectMeta: v1.ObjectMeta{
					Name: fmt.Sprintf("%s-%s", cnp.Name, node),
					Labels: map[string]string{
						"kubernetes.io/networkpolicy-name": cnp.Name,
						"kubernetes.io/node-name":          node,
					},
					OwnerReferences: []v1.OwnerReference{*ownerRef},
				},
				Spec: crdv1alpha1.NetworkPolicyRuleGroupSpec{
					Policy:   cnp.Name,
					NodeName: node,
				},
			}
		}
		switch direction {
		case "ingress":
			rules[node].Spec.Rules = append(rules[node].Spec.Rules, crdv1alpha1.NodeRule{
				Direction:   "ingress",
				Priority:    cnp.Spec.Priority,
				Protocol:    rule.Protocol,
				Action:      string(*rule.Action),
				Ports:       rule.Ports,
				ToAddresses: ads,
				FromAddress: addresses,
				FromIPBlock: ipBlock,
				Http:        http,
			})
		case "egress":
			rules[node].Spec.Rules = append(rules[node].Spec.Rules, crdv1alpha1.NodeRule{
				Direction:   "egress",
				Priority:    cnp.Spec.Priority,
				Protocol:    rule.Protocol,
				Action:      string(*rule.Action),
				Ports:       rule.Ports,
				ToAddresses: addresses,
				FromAddress: ads,
				ToIPBlock:   ipBlock,
				Http:        http,
			})
		default:
			logging.Get().Error().Msgf("invalid rule direction %s ", direction)
		}
	}
	return rules
}

func (npc *NetworkPolicyController) caculatePolicyRulesOnAllNodes(cnp *crdv1alpha1.MicrosegClusterNetworkPolicy) (map[string]*crdv1alpha1.NetworkPolicyRuleGroup, error) {
	ruleGroup := map[string]*crdv1alpha1.NetworkPolicyRuleGroup{}
	addressesMap, err := npc.caculateAddressMap(cnp.Spec.PodSelector, cnp.Spec.NamespaceSelector, cnp.Spec.Group)
	if err != nil {
		return nil, err
	}
	if len(addressesMap) == 0 {
		logging.Get().Warn().Msg("empty node-address map!")
		return ruleGroup, nil
	}
	r1, err := npc.caculateIngressRules(cnp, addressesMap)
	if err != nil {
		return nil, err
	}
	appendToMap(ruleGroup, r1)

	r2, err := npc.caculateEgressRules(cnp, addressesMap)
	if err != nil {
		return nil, err
	}
	appendToMap(ruleGroup, r2)
	return ruleGroup, nil
}

func (npc *NetworkPolicyController) caculateIngressRemoteSideRules(cnp *crdv1alpha1.MicrosegClusterNetworkPolicy, r crdv1alpha1.Rule, peer crdv1alpha1.NetworkPolicyPeer, addresses []crdv1alpha1.Address) (map[string]*crdv1alpha1.NetworkPolicyRuleGroup, error) {
	ruleGroup := map[string]*crdv1alpha1.NetworkPolicyRuleGroup{}
	addresMap, err := npc.caculateAddressMap(peer.PodSelector, peer.NamespaceSelector, peer.Group)
	if err != nil {
		return nil, err
	}
	for node, ads := range addresMap {
		if _, ok := ruleGroup[node]; !ok {
			ownerRef := v1.NewControllerRef(cnp, schema.GroupVersionKind{Group: "microsegmentation.security.io", Version: "v1alpha1", Kind: "MicrosegClusterNetworkPolicy"})
			ruleGroup[node] = &crdv1alpha1.NetworkPolicyRuleGroup{
				ObjectMeta: v1.ObjectMeta{
					Name: fmt.Sprintf("%s-%s", cnp.Name, node),
					Labels: map[string]string{
						"kubernetes.io/networkpolicy-name": cnp.Name,
						"kubernetes.io/node-name":          node,
					},
					OwnerReferences: []v1.OwnerReference{*ownerRef},
				},
				Spec: crdv1alpha1.NetworkPolicyRuleGroupSpec{
					Policy:   cnp.Name,
					NodeName: node,
				},
			}
		}
		ruleGroup[node].Spec.Rules = append(ruleGroup[node].Spec.Rules, crdv1alpha1.NodeRule{
			Direction:   "egress",
			Priority:    cnp.Spec.Priority,
			Protocol:    r.Protocol,
			Action:      string(*r.Action),
			Ports:       r.Ports,
			ToAddresses: addresses,
			FromAddress: ads,
			Http:        peer.Http,
		})
	}
	return ruleGroup, nil
}

func (npc *NetworkPolicyController) caculateEgressRemoteSideRules(cnp *crdv1alpha1.MicrosegClusterNetworkPolicy, r crdv1alpha1.Rule, peer crdv1alpha1.NetworkPolicyPeer, addresses []crdv1alpha1.Address) (map[string]*crdv1alpha1.NetworkPolicyRuleGroup, error) {
	ruleGroup := map[string]*crdv1alpha1.NetworkPolicyRuleGroup{}
	addresMap, err := npc.caculateAddressMap(peer.PodSelector, peer.NamespaceSelector, peer.Group)
	if err != nil {
		return nil, err
	}
	for node, ads := range addresMap {
		if _, ok := ruleGroup[node]; !ok {
			ownerRef := v1.NewControllerRef(cnp, schema.GroupVersionKind{Group: "microsegmentation.security.io", Version: "v1alpha1", Kind: "MicrosegClusterNetworkPolicy"})
			ruleGroup[node] = &crdv1alpha1.NetworkPolicyRuleGroup{
				ObjectMeta: v1.ObjectMeta{
					Name: fmt.Sprintf("%s-%s", cnp.Name, node),
					Labels: map[string]string{
						"kubernetes.io/networkpolicy-name": cnp.Name,
						"kubernetes.io/node-name":          node,
					},
					OwnerReferences: []v1.OwnerReference{*ownerRef},
				},
				Spec: crdv1alpha1.NetworkPolicyRuleGroupSpec{
					Policy:   cnp.Name,
					NodeName: node,
				},
			}
		}
		ruleGroup[node].Spec.Rules = append(ruleGroup[node].Spec.Rules, crdv1alpha1.NodeRule{
			Direction:   "ingress",
			Priority:    cnp.Spec.Priority,
			Protocol:    r.Protocol,
			Action:      string(*r.Action),
			Ports:       r.Ports,
			ToAddresses: ads,
			FromAddress: addresses,
			Http:        peer.Http,
		})
	}
	return ruleGroup, nil
}

func appendToMap(m1 map[string]*crdv1alpha1.NetworkPolicyRuleGroup, m2 map[string]*crdv1alpha1.NetworkPolicyRuleGroup) {
	for k := range m2 {
		if _, ok := m1[k]; ok {
			m1[k].Spec.Rules = append(m1[k].Spec.Rules, m2[k].Spec.Rules...)
		} else {
			m1[k] = m2[k]
		}
	}
}

func (npc *NetworkPolicyController) caculateIngressRules(cnp *crdv1alpha1.MicrosegClusterNetworkPolicy, addressesMap map[string][]crdv1alpha1.Address) (map[string]*crdv1alpha1.NetworkPolicyRuleGroup, error) {
	rules := map[string]*crdv1alpha1.NetworkPolicyRuleGroup{}
	var err error
	var subjectAddress []crdv1alpha1.Address
	for _, v := range addressesMap {
		subjectAddress = append(subjectAddress, v...)
	}

	for _, r := range cnp.Spec.Ingress {
		if len(r.From) == 0 {
			ruleMap := generateCRDPolicyRule(cnp, &r, addressesMap, []crdv1alpha1.Address{{IP: "0.0.0.0"}}, nil, nil, "ingress")
			appendToMap(rules, ruleMap)
			continue
		}
		for _, peer := range r.From {
			var adddress []crdv1alpha1.Address
			if peer.PodSelector == nil && peer.NamespaceSelector == nil && peer.Group == "" && peer.IPBlock == nil {
				adddress = append(adddress, crdv1alpha1.Address{IP: "0.0.0.0"})
			} else {
				adddress, err = npc.caculateAddress(peer.PodSelector, peer.NamespaceSelector, peer.Group)
				if err != nil {
					return nil, err
				}
			}
			if len(adddress) == 0 && peer.IPBlock == nil {
				logging.Get().Info().Msg("empty address inside egress rules")
				continue
			}
			// generate ingress rules for subject pods
			//  from ------> subject
			rule1 := generateCRDPolicyRule(cnp, &r, addressesMap, adddress, peer.IPBlock, peer.Http, "ingress")
			appendToMap(rules, rule1)

			// generate egress rules for from-side pods
			rule2, err := npc.caculateIngressRemoteSideRules(cnp, r, peer, subjectAddress)
			if err != nil {
				return nil, err
			}
			appendToMap(rules, rule2)
		}
	}
	return rules, nil
}

func (npc *NetworkPolicyController) caculateEgressRules(cnp *crdv1alpha1.MicrosegClusterNetworkPolicy, addressesMap map[string][]crdv1alpha1.Address) (map[string]*crdv1alpha1.NetworkPolicyRuleGroup, error) {
	var err error
	rules := map[string]*crdv1alpha1.NetworkPolicyRuleGroup{}
	var subjectAddress []crdv1alpha1.Address
	for _, v := range addressesMap {
		subjectAddress = append(subjectAddress, v...)
	}

	for _, r := range cnp.Spec.Egress {
		if len(r.To) == 0 {
			ruleMap := generateCRDPolicyRule(cnp, &r, addressesMap, []crdv1alpha1.Address{{IP: "0.0.0.0"}}, nil, nil, "egress")
			appendToMap(rules, ruleMap)
			continue
		}
		for _, peer := range r.To {
			var toAddresses []crdv1alpha1.Address
			var endpoints []endPoint
			if peer.PodSelector == nil && peer.NamespaceSelector == nil && peer.Group == "" && peer.IPBlock == nil {
				toAddresses = []crdv1alpha1.Address{{IP: "0.0.0.0"}}
			} else {
				// endpoints, err = npc.getRelatedServiceAddr(peer.PodSelector, peer.NamespaceSelector, peer.Group, r.Ports)
				// if err != nil {
				// 	return nil, err
				// }

				toAddresses, err = npc.caculateAddress(peer.PodSelector, peer.NamespaceSelector, peer.Group)
				if err != nil {
					return nil, err
				}
			}

			if len(toAddresses) == 0 && peer.IPBlock == nil && len(endpoints) == 0 {
				logging.Get().Info().Msg("empty address in egress rules")
				continue
			}

			// generate egress rule for subject pods
			rule1 := generateCRDPolicyRule(cnp, &r, addressesMap, toAddresses, peer.IPBlock, peer.Http, "egress")
			for node, ads := range addressesMap {
				for _, ep := range endpoints {
					rule1[node].Spec.Rules = append(rule1[node].Spec.Rules, crdv1alpha1.NodeRule{
						Direction:   "egress",
						Priority:    cnp.Spec.Priority,
						Protocol:    r.Protocol,
						Action:      string(*r.Action),
						Ports:       ep.Ports,
						ToAddresses: []crdv1alpha1.Address{{IP: ep.Address}},
						FromAddress: ads,
					})
				}
			}
			appendToMap(rules, rule1)

			// generate ingress rules for to-side pods
			rule2, err := npc.caculateEgressRemoteSideRules(cnp, r, peer, subjectAddress)
			if err != nil {
				return nil, err
			}
			appendToMap(rules, rule2)
		}
	}
	return rules, nil
}
