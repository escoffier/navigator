package nodeinfo

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"

	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	DockerType = "docker"
	CrioType   = "cri-o"
	PodmanType = "podman"
)

const PodUIDIndex = "podUID"

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

func (p *PodEvent) FinalOwnerResource(ctx context.Context) *Resource {
	if p.finalOwnerResource == nil {
		p.Lock()
		defer p.Unlock()

		p.finalOwnerResource = p.fetchFunc(ctx, p.Pod)
	}
	return p.finalOwnerResource
}

type PodWatcher interface {
	OnAdd(newPod *PodEvent)
	OnDelete(oldPod *PodEvent)
	OnUpdate(oldPod, newPod *PodEvent)
	Name() string
}
type NodePodsWatcher struct {
	watchers    []PodWatcher
	store       cache.Indexer
	controller  cache.Controller
	k8sClient   *kubernetes.Clientset
	ownRefCache *ownerRefCache

	NodeName   string
	clusterKey string
}

type Builder struct {
	instance *NodePodsWatcher
}

func NewNodePodsWatcher(nodeName, clusterKey string) *Builder {
	return &Builder{
		instance: &NodePodsWatcher{
			watchers:    make([]PodWatcher, 0, 3),
			NodeName:    nodeName,
			ownRefCache: newOwnerRefCache(50, 30*time.Minute),
			clusterKey:  clusterKey,
		},
	}
}

func (b *Builder) AddWatcher(pw PodWatcher) *Builder {
	b.instance.watchers = append(b.instance.watchers, pw)
	return b
}

func (b *Builder) Build() *NodePodsWatcher {
	return b.instance
}

func (n *NodePodsWatcher) InitK8sClient() (*kubernetes.Clientset, error) {
	config, err := k8s.KubeConfig()
	if err != nil {
		return nil, errors.Errorf("Couldn't initialize k8s config: %w", err)
	}
	// k8s client
	n.k8sClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Errorf("Couldn't initialize k8s clientset: %w", err)
	}

	return n.k8sClient, nil
}

func (n *NodePodsWatcher) GetContainerType() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	node, err := n.k8sClient.CoreV1().Nodes().Get(ctx, n.NodeName, metav1.GetOptions{})
	if err != nil {
		return "", errors.Errorf("get node info failed, %v", err)
	}

	containerType := node.Status.NodeInfo.ContainerRuntimeVersion
	ok := strings.Contains(containerType, "docker")
	if ok {
		return DockerType, nil
	}

	ok = strings.Contains(containerType, "cri-o")
	if ok {
		return CrioType, nil
	}

	ok = strings.Contains(containerType, "podman")
	if ok {
		return PodmanType, nil
	}

	return "", errors.Errorf("can not support this container type")
}

func (n *NodePodsWatcher) getFinalResourceOfPod(ctx context.Context, pod *corev1.Pod) (name string, kind string) {
	if pod == nil {
		return name, kind
	}

	owner := metav1.GetControllerOf(pod)
	if owner == nil {
		kind = pod.Kind
		if len(kind) == 0 {
			kind = "Pod"
		}
		return pod.GetName(), kind
	}

	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	switch owner.Kind {
	case "ReplicaSet":
		ownerRes, exist := n.ownRefCache.GetOwnerFrom(owner.Name, owner.Kind, pod.Namespace)
		if exist {
			return ownerRes.Name, ownerRes.Kind
		}

		rs, err := n.k8sClient.AppsV1().ReplicaSets(pod.Namespace).Get(tctx, owner.Name, metav1.GetOptions{})
		if err != nil {
			logging.Get().Err(err).Msgf("get replicaset for %s/%s error", pod.Namespace, owner.Name)
			return owner.Name, owner.Kind
		}
		nextOwner := metav1.GetControllerOf(rs)
		if nextOwner != nil {
			err = n.ownRefCache.Put(owner.Name, owner.Kind, pod.Namespace, Resource{
				Name: nextOwner.Name,
				Kind: nextOwner.Kind,
			})
			if err != nil {
				logging.Get().Warn().Msgf("Put to owner cache error: %v. data: %+v -> %+v", err, owner, nextOwner)
			}
			return nextOwner.Name, nextOwner.Kind
		}
		return owner.Name, owner.Kind
	case "Job":
		ownerRes, exist := n.ownRefCache.GetOwnerFrom(owner.Name, owner.Kind, pod.Namespace)
		if exist {
			return ownerRes.Name, ownerRes.Kind
		}

		job, err := n.k8sClient.BatchV1().Jobs(pod.Namespace).Get(tctx, owner.Name, metav1.GetOptions{})
		if err != nil {
			logging.Get().Err(err).Msgf("get job for %s/%s error", pod.Namespace, owner.Name)
			return owner.Name, owner.Kind
		}
		nextOwner := metav1.GetControllerOf(job)
		if nextOwner != nil {
			err = n.ownRefCache.Put(owner.Name, owner.Kind, pod.Namespace, Resource{
				Name: nextOwner.Name,
				Kind: nextOwner.Kind,
			})
			if err != nil {
				logging.Get().Warn().Msgf("Put to owner cache error: %v. data: %+v -> %+v", err, owner, nextOwner)
			}
			return nextOwner.Name, nextOwner.Kind
		}
		return owner.Name, owner.Kind
	default:
		return owner.Name, owner.Kind
	}
}

func (n *NodePodsWatcher) Start(ctx context.Context) (err error) {

	watchlist := cache.NewFilteredListWatchFromClient(
		n.k8sClient.CoreV1().RESTClient(),
		string(corev1.ResourcePods),
		corev1.NamespaceAll,
		func(options *metav1.ListOptions) {
			options.FieldSelector = fmt.Sprintf("spec.nodeName=%v", n.NodeName)
		},
	)
	n.store, n.controller = cache.NewIndexerInformer(
		watchlist,
		&corev1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if obj == nil {
					return
				}
				if pod, ok := obj.(*corev1.Pod); ok {
					defer func() {
						if r := recover(); r != nil {
							logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
						}
					}()
					podEvt := newPodEvent(pod, func(ctx context.Context, pod *corev1.Pod) *Resource {
						finalRes, finalKind := n.getFinalResourceOfPod(ctx, pod)
						return &Resource{
							Name: finalRes,
							Kind: finalKind,
						}
					})

					for _, w := range n.watchers {
						w.OnAdd(podEvt)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				if obj == nil {
					return
				}
				if pod, ok := obj.(*corev1.Pod); ok {
					defer func() {
						if r := recover(); r != nil {
							logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
						}
					}()

					podEvt := newPodEvent(pod, func(ctx context.Context, pod *corev1.Pod) *Resource {
						finalRes, finalKind := n.getFinalResourceOfPod(ctx, pod)
						return &Resource{
							Name: finalRes,
							Kind: finalKind,
						}
					})

					for _, w := range n.watchers {
						w.OnDelete(podEvt)
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if newObj == nil || oldObj == nil {
					return
				}
				if oldPod, ok0 := oldObj.(*corev1.Pod); ok0 {
					if newPod, ok1 := newObj.(*corev1.Pod); ok1 {
						defer func() {
							if r := recover(); r != nil {
								logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
							}
						}()

						newPodEvt := newPodEvent(newPod, func(ctx context.Context, pod *corev1.Pod) *Resource {
							finalRes, finalKind := n.getFinalResourceOfPod(ctx, pod)
							return &Resource{
								Name: finalRes,
								Kind: finalKind,
							}
						})
						oldPodEvt := newPodEvent(oldPod, func(ctx context.Context, pod *corev1.Pod) *Resource {
							finalRes, finalKind := n.getFinalResourceOfPod(ctx, pod)
							return &Resource{
								Name: finalRes,
								Kind: finalKind,
							}
						})
						for _, w := range n.watchers {
							w.OnUpdate(oldPodEvt, newPodEvt)
						}
					}
				}
			},
		},
		cache.Indexers{},
	)
	n.store.AddIndexers(cache.Indexers{PodUIDIndex: func(obj interface{}) ([]string, error) {
		pod, ok := obj.(*corev1.Pod)
		if ok {
			return []string{string(pod.UID)}, nil
		}
		return nil, fmt.Errorf("object is not pod")
	}})

	stopChan := make(chan struct{}, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		n.controller.Run(stopChan)
	}()

	// wait for 10 seconds for sync
	for i := 0; i < 10; i++ {
		if n.controller.HasSynced() {
			logging.Get().Info().Msg("the node pods controller has synced")
			break
		}
		time.Sleep(1 * time.Second)
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
	for _, p := range objs {
		pod := p.(*corev1.Pod)

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
		break
	}

	return tensorPod, nil
}
