package assets

import (
	"context"
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
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

func (cb *HoneyspotCallback) OnRawContainer(*assets.TensorRawContainer, assets.Action) error {
	return nil
}

func (cb *HoneyspotCallback) OnSync(*assets.TensorSync) error {
	return nil
}

type HoneyspotEvent struct {
	clusterKey string
	object     *defensev1.Honeypot
	action     assets.Action
	updateTime time.Time
}

func (cb *HoneyspotService) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.Pods2Watch:            {},
		assets.TensorResources2Watch: {},
	}
}

func (cb *HoneyspotService) BeforeWatchNewCluster(_ context.Context, clusterKey string, _ time.Duration) assets.ClusterCallback {
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

func (cb *HoneyspotCallback) OnHoneyspot(honeySpot *assets.TensorHoneySpot, action assets.Action) error {
	var event HoneyspotEvent

	event.clusterKey = honeySpot.Cluster
	event.object = honeySpot.Honeypot
	event.action = action
	event.updateTime = time.Now()

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
		err = dal.UpdateBaitServiceWLStatus(context.Background(), cb.parent.rdb.Get(), id, 0, event.object.Status.WorkLoadStatus)
		if err != nil {
			logging.Get().Err(err).Msg("upsert honeyspot in rdb error")
			return err
		}
	}
	return nil
}

func (cb *HoneyspotCallback) OnTensorResourceEvent(newResource, oldResource *assets.TensorResource, action assets.Action) error {
	return nil
}

func (cb *HoneyspotCallback) OnTensorPod(*assets.TensorPod, assets.Action) error {
	return nil
}

func (cb *HoneyspotCallback) OnTensorRole(*assets.TensorRole, assets.Action) error {
	return nil
}

func (cb *HoneyspotCallback) OnTensorClusterRole(*assets.TensorClusterRole, assets.Action) error {
	return nil
}

func (cb *HoneyspotCallback) OnTensorIngress(*assets.TensorIngress, assets.Action) error {
	return nil
}

func (cb *HoneyspotCallback) OnTensorService(*assets.TensorService, assets.Action) error {
	return nil
}

func (cb *HoneyspotCallback) OnTensorEndpoints(*assets.TensorEndpoints, assets.Action) error {
	return nil
}

func (cb *HoneyspotCallback) OnTensorSecret(*assets.TensorSecret, assets.Action) error {
	return nil
}

func (cb *HoneyspotCallback) OnTensorPV(*assets.TensorPV, assets.Action) error {
	return nil
}

func (cb *HoneyspotCallback) OnTensorPVC(*assets.TensorPVC, assets.Action) error {
	return nil
}

func (cb *HoneyspotCallback) OnTensorNamespace(*assets.TensorNamespace, assets.Action) error {
	return nil
}

func (cb *HoneyspotCallback) OnTensorNode(*assets.TensorNode, assets.Action) error {
	return nil
}

func (cb *HoneyspotCallback) AfterDataSynced(context.Context, bool, string) {
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
