package leaderelection

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/security-rd/go-pkg/logging"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	kubeleletcion "k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

type Elector struct {
	leaderElector *kubeleletcion.LeaderElector
	namespace     string
	podName       string
}

func New(f func(context.Context), opts *flag.ElectionOpts) (*Elector, error) {
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	kubeConfig.QPS = 100
	kubeConfig.Burst = 100
	client, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("unable to get hostname: %v", err)
	}
	namespace := os.Getenv("MY_POD_NAMESPACE")
	podName := os.Getenv("MY_POD_NAME")
	lockName := os.Getenv("MY_POD_APP_LABEl")

	id := hostname + "_" + uuid.New().String()
	logging.Get().Info().Msgf("my election id: %s", id)
	lock := &resourcelock.LeaseLock{
		LeaseMeta: v1.ObjectMeta{
			Name:      lockName,
			Namespace: namespace,
		},
		Client: client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: id,
		},
	}

	config := kubeleletcion.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   opts.LeaseDuration,
		RenewDeadline:   opts.RenewDeadline,
		RetryPeriod:     opts.RetryPeriod,
		Callbacks: kubeleletcion.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				go f(ctx)
				setPodRole(client, namespace, podName, "leader")
			},
			OnStoppedLeading: func() {
				// we can do cleanup here
				logging.Get().Info().Msgf("leader lost: %s", id)
				os.Exit(0)
			},
			OnNewLeader: func(identity string) {
				// we're notified when new leader elected
				if identity == id {
					// I just got the lock
					return
				}
				setPodRole(client, namespace, podName, "follower")
				logging.Get().Info().Msgf("new leader elected: %s", identity)
			},
		},
	}
	l, err := kubeleletcion.NewLeaderElector(config)
	if err != nil {
		return nil, err
	}
	return &Elector{
		leaderElector: l,
		namespace:     namespace,
		podName:       podName,
	}, nil
}

func setPodRole(client *kubernetes.Clientset, namespace, podName, role string) {
	type Patch struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value string `json:"value"`
	}

	patch := []Patch{
		{
			Op:    "add",
			Path:  "/metadata/labels/" + "election.status",
			Value: role,
		},
	}
	data, err := json.Marshal(patch)
	if err != nil {
		logging.Get().Info().Msgf("marshal pod election label err %v", err)
		return
	}
	_, err = client.CoreV1().Pods(namespace).Patch(context.TODO(), podName, types.JSONPatchType, data, v1.PatchOptions{})
	if err != nil {
		logging.Get().Info().Msgf("patch pod election label err %v", err)
		return
	}
}

func (e *Elector) Run(ctx context.Context) {
	e.leaderElector.Run(ctx)
}
