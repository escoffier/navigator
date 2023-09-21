package nodeinfo

import (
	"context"
	"fmt"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	listerv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	DockerType     = "docker"
	CrioType       = "cri-o"
	PodmanType     = "podman"
	ContainerdType = "containerd"
	PodUIDIndex    = "podUID"
	PodIPIndex     = "podIP"
)

var cronJobNameRegexp = regexp.MustCompile(`(.+)-\d{8,10}$`)

func ExtractPod(obj any) *corev1.Pod {
	var empty *corev1.Pod
	if obj == nil {
		return empty
	}
	o, ok := obj.(*corev1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			logging.Get().Error().Msgf("couldn't get object from tombstone: %+v", obj)
			return empty
		}
		o, ok = tombstone.Obj.(*corev1.Pod)
		if !ok {
			logging.Get().Error().Msgf("tombstone contained object that is not an object (key:%v, obj:%T)", tombstone.Key, tombstone.Obj)
			return empty
		}
	}
	return o
}

func stripUnusedFields(obj any) (any, error) {
	o, ok := obj.(metav1.ObjectMetaAccessor)
	if !ok {
		return obj, nil
	}
	o.GetObjectMeta().SetManagedFields(nil)
	return o, nil
}

type PodEventHandlerFuncs struct {
	AddFunc    func(obj *corev1.Pod)
	UpdateFunc func(oldObj, newObj *corev1.Pod)
	DeleteFunc func(obj *corev1.Pod)
}

// OnAdd calls AddFunc if it's not nil.
func (r PodEventHandlerFuncs) OnAdd(obj interface{}) {
	if r.AddFunc != nil {
		r.AddFunc(ExtractPod(obj))
	}
}

// OnUpdate calls UpdateFunc if it's not nil.
func (r PodEventHandlerFuncs) OnUpdate(oldObj, newObj interface{}) {
	if r.UpdateFunc != nil {
		r.UpdateFunc(ExtractPod(oldObj), ExtractPod(newObj))
	}
}

// OnDelete calls DeleteFunc if it's not nil.
func (r PodEventHandlerFuncs) OnDelete(obj interface{}) {
	if r.DeleteFunc != nil {
		r.DeleteFunc(ExtractPod(obj))
	}
}

type Resource struct {
	Name string
	Kind string
}

type PodEvent struct {
	Pod                *corev1.Pod
	finalOwnerResource *Resource
	fetchFunc          func(ctx context.Context, pod *corev1.Pod) *Resource
	sync.Mutex
}

type TensorPod struct {
	ClusterKey string   `json:"clusterKey"`
	Namespace  string   `json:"namespace"`
	Name       string   `json:"name"`
	Containers []string `json:"containers"`
}

func newPodEvent(pod *corev1.Pod, ffunc func(ctx context.Context, pod *corev1.Pod) *Resource) *PodEvent {
	return &PodEvent{
		Pod:       pod,
		fetchFunc: ffunc,
	}
}

type PodWatcher interface {
	OnAdd(newPod *PodEvent, containerInfo ContainerInfoManager)
	OnDelete(oldPod *PodEvent)
	OnUpdate(oldPod, newPod *PodEvent, containerInfo ContainerInfoManager)
	Name() string
}

type NodePodsWatcher struct {
	store      cache.Indexer
	podLister  listerv1.PodLister
	k8sClient  *kubernetes.Clientset
	informer   cache.SharedIndexInformer
	NodeName   string
	clusterKey string
}

func (n *NodePodsWatcher) Store() cache.Indexer {
	return n.store
}

type Builder struct {
	instance *NodePodsWatcher
}

func NewNodePodsWatcher(nodeName, clusterKey string, kubeClient *kubernetes.Clientset) *Builder {
	n := &NodePodsWatcher{
		NodeName:   nodeName,
		clusterKey: clusterKey,
		k8sClient:  kubeClient,
	}
	logging.Get().Info().Str("base", "pods").Msgf("start watching pod on node %s", n.NodeName)
	n.informer = v1.NewFilteredPodInformer(kubeClient, corev1.NamespaceAll, 0, cache.Indexers{}, func(lo *metav1.ListOptions) {
		lo.FieldSelector = "spec.nodeName=" + n.NodeName
	})
	n.informer.SetTransform(stripUnusedFields)
	n.store = n.informer.GetIndexer()
	n.podLister = listerv1.NewPodLister(n.informer.GetIndexer())
	n.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)
			logging.Get().Info().Str("base", "pods").Msgf("add pod %s/%s", pod.Namespace, pod.Name)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newPod := newObj.(*corev1.Pod)
			logging.Get().Info().Str("base", "pods").Msgf("update pod %s/%s", newPod.Namespace, newPod.Name)
		},
		DeleteFunc: func(obj interface{}) {
			pod := GetPodFromDeleteAction(obj)
			logging.Get().Info().Str("base", "pods").Msgf("delete pod %s/%s", pod.Namespace, pod.Name)
		},
	})
	n.informer.AddIndexers(cache.Indexers{
		PodUIDIndex: func(obj interface{}) ([]string, error) {
			pod, ok := obj.(*corev1.Pod)
			if ok {
				return []string{string(pod.UID)}, nil
			}
			return nil, fmt.Errorf("object is not pod")
		},
		PodIPIndex: func(obj interface{}) ([]string, error) {
			pod, ok := obj.(*corev1.Pod)
			if ok {
				return []string{string(pod.Status.PodIP)}, nil
			}
			return nil, fmt.Errorf("object is not pod")
		},
	})

	return &Builder{
		instance: n,
	}
}

func (b *Builder) AddEventHandler(handler cache.ResourceEventHandler) *Builder {
	b.instance.informer.AddEventHandler(handler)
	return b
}

func (b *Builder) Build() *NodePodsWatcher {
	return b.instance
}

func (n *NodePodsWatcher) GetContainerType() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	node, err := n.k8sClient.CoreV1().Nodes().Get(ctx, n.NodeName, metav1.GetOptions{})
	if err != nil {
		return "", errors.Errorf("get node info failed, %v", err)
	}

	containerType := node.Status.NodeInfo.ContainerRuntimeVersion
	ok := strings.Contains(containerType, DockerType)
	if ok {
		return DockerType, nil
	}

	ok = strings.Contains(containerType, "runtime")
	if ok {
		return DockerType, nil
	}

	ok = strings.Contains(containerType, CrioType)
	if ok {
		return CrioType, nil
	}

	ok = strings.Contains(containerType, PodmanType)
	if ok {
		return PodmanType, nil
	}
	ok = strings.Contains(containerType, ContainerdType)
	if ok {
		return ContainerdType, nil
	}

	return "", errors.Errorf("can not support this container type:" + containerType)
}

func GetPodFromDeleteAction(obj interface{}) *corev1.Pod {
	if pod, ok := obj.(*corev1.Pod); ok {
		// Enqueue all the services that the pod used to be a member of.
		// This is the same thing we do when we add a pod.
		return pod
	}
	// If we reached here it means the pod was deleted but its final state is unrecorded.
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		logging.Get().Warn().Msgf("Couldn't get object from tombstone %#v", obj)
		// utilruntime.HandleError(fmt.Errorf("Couldn't get object from tombstone %#v", obj))
		return nil
	}
	pod, ok := tombstone.Obj.(*corev1.Pod)
	if !ok {
		logging.Get().Warn().Msgf("Tombstone contained object that is not a Pod: %#v", obj)
		return nil
	}
	return pod
}

func (n *NodePodsWatcher) syncPod(key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	pod, err := n.podLister.Pods(namespace).Get(name)
	if err != nil {
		return err
	}
	logging.Get().Info().Msgf("pod: %+v", pod)
	return nil
}

func (n *NodePodsWatcher) Start(ctx context.Context, stop <-chan struct{}) (err error) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		n.informer.Run(stop)
	}()

	if !cache.WaitForCacheSync(stop, n.informer.HasSynced) {
		return fmt.Errorf("pod cache sync err")
	}
	return nil
}

func (n *NodePodsWatcher) GetPodByUID(uid string) (*TensorPod, error) {
	objs, err := n.store.ByIndex(PodUIDIndex, uid)
	if err != nil {
		return nil, err
	}
	if len(objs) == 0 {
		return nil, fmt.Errorf("pod not found")
	}
	var tensorPod *TensorPod
	pod := objs[0].(*corev1.Pod)

	containers := []string{}
	for _, c := range pod.Spec.Containers {
		containers = append(containers, c.Name)
	}
	tensorPod = &TensorPod{
		ClusterKey: n.clusterKey,
		Namespace:  pod.Namespace,
		Name:       pod.Name,
		Containers: containers,
	}

	return tensorPod, nil
}

func (n *NodePodsWatcher) GetPodOwner(namespace, name string) (string, string, error) {
	obj, exists, err := n.store.GetByKey(namespace + "/" + name)
	if err != nil {
		return "", "", err
	}
	if !exists {
		return "", "", errors.Errorf("pod %s not found", namespace+"/"+name)
	}
	pod := obj.(*corev1.Pod)
	resName, resKind := util.GetOwnerOfPod(pod)
	return resName, resKind, nil
}

func (n *NodePodsWatcher) GetPod(namespace, name string) (*corev1.Pod, error) {
	obj, exists, err := n.store.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.Errorf("pod %s not found", namespace+"/"+name)
	}
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, errors.New("invalid pod object")
	}
	return pod, nil
}
