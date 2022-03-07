package assets

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/util/workqueue"
	defensev1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/defense/v1"
)

type HoneyspotService struct {
	rdb   *databases.RDBInstance
	Queue workqueue.RateLimitingInterface
}

type HoneyspotCallback struct {
	clusterKey       string
	parent           *HoneyspotService
	Queue            workqueue.RateLimitingInterface
	refreshTimestamp int64
}

type HoneyspotEvent struct {
	object     *defensev1.Honeypot
	action     assets.AssetsAction
	updateTime time.Time
}

func (cb *HoneyspotService) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.Pods2Watch:            {},
		assets.TensorResources2Watch: {},
	}
}

func (cb *HoneyspotService) BeforWatchNewCluster(ctx context.Context, clusterKey string, resyncInterval time.Duration) assets.ClusterCallback {
	logging.Get().Info().Msgf("honeyspot assets before watch new cluster %s called.", clusterKey)

	ccb := &HoneyspotCallback{
		clusterKey:       clusterKey,
		parent:           cb,
		refreshTimestamp: time.Now().Unix(),
		Queue:            cb.Queue,
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. stack: %s", r, debug.Stack())
			}
		}()
		logging.Get().Info().Msg("start to consume honeyspot")
		for {
			object, shutdown := cb.Queue.Get()
			if shutdown {
				return
			}

			honeyspotEvent, ok := object.(HoneyspotEvent)
			if !ok {
				cb.Queue.Forget(object)
			}

			err := ccb.processHoneyspot(honeyspotEvent)
			if err != nil {
				if cb.Queue.NumRequeues(object) < 5 {
					cb.Queue.AddRateLimited(object)
				} else {
					cb.Queue.Forget(object)
				}
			}
		}
	}()

	return ccb
}

// Name returns the name
func (cb *HoneyspotService) Name() string {
	return "honeyspot"
}
func newHoneyspotService(rdb *databases.RDBInstance) *HoneyspotService {
	return &HoneyspotService{
		rdb:   rdb,
		Queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "honeyspot"),
	}
}

func (cb *HoneyspotCallback) Name() string {
	return cb.parent.Name()
}

func (cb *HoneyspotCallback) OnHoneyspot(newHoneyspot, oldHoneyspot *defensev1.Honeypot, action assets.AssetsAction) error {
	var event HoneyspotEvent
	if action == assets.ActionDelete {
		if oldHoneyspot == nil {
			return errors.New("not given old honeyspot")
		}

		event.object = oldHoneyspot
		event.action = action
		event.updateTime = time.Now()
	} else if action == assets.ActionAdd || action == assets.ActionUpdate {
		if newHoneyspot == nil {
			return errors.New("not given new honeyspot")
		}
		event.object = newHoneyspot
		event.action = action
		event.updateTime = time.Now()

	}

	cb.Queue.Add(event)
	return nil
}

func (cb *HoneyspotCallback) processHoneyspot(event HoneyspotEvent) error {
	id, err := getBaitServiceID(event.object.Name)
	if err != nil {
		logging.Get().Err(err).Msg("cann't get baitservice id")
		return err
	}

	switch event.action {
	case assets.ActionDelete:

		logging.Get().Info().Msgf("delete honeyspot %d", id)
		err = dal.DeleteBaitServiceById(context.TODO(), cb.parent.rdb.Get(), id)
		if err != nil {
			logging.Get().Err(err).Msg("delete pod resource rel in rdb error")
			return err
		}
	case assets.ActionUpdate, assets.ActionAdd:
		logging.Get().Info().Msgf("update honeyspot %d, WorkLoadStatus: %s", id, event.object.Status.WorkLoadStatus)

		if event.object.Status.WorkLoadStatus == "" {
			event.object.Status.WorkLoadStatus = "offline"
		}
		err = dal.UpdateBaitService(context.Background(), cb.parent.rdb.Get(), &model.BaitService{
			TableBase: model.TableBase{
				ID:     id,
				Status: 0,
			},
			WorkLoadStatus: event.object.Status.WorkLoadStatus,
		})
		if err != nil {
			logging.Get().Err(err).Msg("upsert honeyspot in rdb error")
			return err
		}
	}
	return nil
}

func (cb *HoneyspotCallback) OnPodEvent(newPod, oldPod *corev1.Pod, action assets.AssetsAction) error {
	return nil
}
func (cb *HoneyspotCallback) OnRoleEvent(newRole, oldRole *rbacv1.Role, action assets.AssetsAction) error {
	return nil
}
func (cb *HoneyspotCallback) OnClusterRoleEvent(newCRole, oldCRole *rbacv1.ClusterRole, action assets.AssetsAction) error {
	return nil
}
func (cb *HoneyspotCallback) OnRoleBindingEvent(newB, oldB *rbacv1.RoleBinding, action assets.AssetsAction) error {
	return nil
}
func (cb *HoneyspotCallback) OnClusterRoleBindingEvent(newB, oldB *rbacv1.ClusterRoleBinding, action assets.AssetsAction) error {
	return nil
}
func (cb *HoneyspotCallback) OnNamespaceEvent(newNs, oldNs *corev1.Namespace, action assets.AssetsAction) error {
	return nil
}
func (cb *HoneyspotCallback) OnServiceAccountEvent(newSa, oldSa *corev1.ServiceAccount, action assets.AssetsAction) error {
	return nil
}

func (cb *HoneyspotCallback) OnEndPointEvent(newEpt, oldEpt *corev1.Endpoints, action assets.AssetsAction) error {
	// ignore endpoint events
	return nil
}
func (cb *HoneyspotCallback) OnServiceEvent(newSvc, oldEvc *corev1.Service, action assets.AssetsAction) error {
	return nil
}

func (cb *HoneyspotCallback) OnNodeEvent(newNode, oldNode *corev1.Node, action assets.AssetsAction) error {
	return nil
}

func (cb *HoneyspotCallback) OnTensorResourceEvent(newResource, oldResource *assets.TensorResource, action assets.AssetsAction) error {
	return nil
}
func (cb *HoneyspotCallback) AfterDataSynced(ctx context.Context, dataSynced bool) {
	// if dataSynced {
	// 	cb.inputQueue.Add(syncSignal{})
	// }
}

func getBaitServiceID(name string) (uint32, error) {
	strs := strings.Split(name, "-")
	len := len(strs)
	if len < 2 {
		return 0, fmt.Errorf("invalid bait service name %s", name)
	}

	id, err := strconv.Atoi(strs[len-1])
	if err != nil {
		return 0, err
	}
	return uint32(id), nil
}
