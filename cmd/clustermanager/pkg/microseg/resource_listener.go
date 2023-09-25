package microseg

import (
	"context"
	"errors"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	model "gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm/clause"
)

const (
	name = "microseg_resources_listener"
)

type ResourcesListener struct {
	rdb *databases.RDBInstance
}

func NewResourcesListener(rdb *databases.RDBInstance) *ResourcesListener {
	return &ResourcesListener{
		rdb: rdb,
	}
}
func (rl *ResourcesListener) BeforeWatchNewCluster(ctx context.Context, clusterName string, resyncTTL time.Duration) assets.ClusterCallback {
	return &ResourcesClusterListener{
		clusterKey: clusterName,
		parent:     rl,
		stTime:     time.Now(),
	}
}
func (rl *ResourcesListener) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.TensorResources2Watch: {},
	}
}
func (rl *ResourcesListener) Name() string {
	return name
}

type ResourcesClusterListener struct {
	clusterKey string
	parent     *ResourcesListener
	stTime     time.Time
}

func (cl *ResourcesClusterListener) OnRawContainer(*assets.TensorRawContainer, assets.Action) error {
	return nil
}

func (cl *ResourcesClusterListener) OnSync(*assets.TensorSync) error {
	return nil
}

func (cl *ResourcesClusterListener) OnTensorPod(*assets.TensorPod, assets.Action) error {
	return nil
}

func newModelFromResource(res *assets.TensorResource) *model.TensorMicrosegResource {
	m := new(model.TensorMicrosegResource)
	m.Cluster = res.Cluster
	m.ID = model.GenID(res.Cluster, res.Namespace, string(res.Kind), res.Name)
	m.Kind = string(res.Kind)
	m.Name = res.Name
	m.Namespace = res.Namespace
	now := time.Now()
	m.CreatedAt = now
	m.UpdatedAt = now
	m.Status = 0
	m.NetworkType = model.PodNetwork
	m.ResourceTag = 0
	if res.PodTemplate != nil && res.PodTemplate.Spec.HostNetwork {
		m.NetworkType = model.HostNetwork
	}
	return m
}
func (cl *ResourcesClusterListener) upsertMicrosegResource(ctx context.Context, res *assets.TensorResource) error {
	newMsRes := newModelFromResource(res)

	db := cl.parent.rdb.Get()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(context.Background(), 1000*time.Millisecond)
		defer oneCancel()
		return db.WithContext(oneCtx).Model(&model.TensorMicrosegResource{}).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns([]string{"updated_at", "status"}),
		}).Create(newMsRes).Error
	})
}
func (cl *ResourcesClusterListener) removeMicrosegResource(ctx context.Context, res *assets.TensorResource) error {
	db := cl.parent.rdb.Get()

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(context.Background(), 1000*time.Millisecond)
		defer oneCancel()
		id := model.GenID(res.Cluster, res.Namespace, string(res.Kind), res.Name)
		return db.WithContext(oneCtx).Model(&model.TensorMicrosegResource{}).Where("id = ?", id).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": time.Now(),
		}).Error
	})
}

func (cl *ResourcesClusterListener) OnTensorResourceEvent(newResource, oldResource *assets.TensorResource, action assets.Action) error {

	switch action {
	case assets.ActionAdd, assets.ActionUpdate:
		if newResource == nil {
			return errors.New("nil resource")
		}

		// Because we have watched the changes of Deployments, the replicasets that are controlled by a Deployment will be ignored
		if assets.ShouldResourceBeFiltered(newResource) {
			return nil
		}
		err := cl.upsertMicrosegResource(context.Background(), newResource)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("ResourcesClusterListener upsert resource error. res: %+v", newResource)
			return err
		}
	case assets.ActionDelete:
		if newResource == nil {
			return errors.New("nil resource")
		}

		// Because we have watched the changes of Deployments, the replicasets that are controlled by a Deployment will be ignored
		if assets.ShouldResourceBeFiltered(newResource) {
			return nil
		}
		err := cl.removeMicrosegResource(context.Background(), newResource)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("ResourcesClusterListener remove resource error. res: %+v", newResource)
			return err
		}
	}
	return nil
}
func (cl *ResourcesClusterListener) AfterDataSynced(ctx context.Context, dataSynced bool, clusterKey string) {
	if !dataSynced {
		return
	}

	db := cl.parent.rdb.Get()

	tctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := util.RetryWithBackoff(tctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(tctx, 3000*time.Millisecond)
		defer oneCancel()

		return db.WithContext(oneCtx).Model(&model.TensorMicrosegResource{}).Where("updated_at < ? AND status = 0 AND cluster = ?", cl.stTime, clusterKey).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": time.Now(),
		}).Error
	})
	if err != nil {
		logging.GetLogger().Err(err).Msg("data synced. update databases error")
	}

}
func (cl *ResourcesClusterListener) OnHoneyspot(honeyspot *assets.TensorHoneySpot, action assets.Action) error {
	return nil
}

func (cl *ResourcesClusterListener) OnTensorRole(tensorRole *assets.TensorRole, action assets.Action) error {
	return nil
}

func (cl *ResourcesClusterListener) OnTensorClusterRole(tensorRole *assets.TensorClusterRole, action assets.Action) error {
	return nil
}

func (cl *ResourcesClusterListener) OnTensorIngress(*assets.TensorIngress, assets.Action) error {
	return nil
}

func (cl *ResourcesClusterListener) OnTensorService(*assets.TensorService, assets.Action) error {
	return nil
}

func (cl *ResourcesClusterListener) OnTensorEndpoints(*assets.TensorEndpoints, assets.Action) error {
	return nil
}

func (cl *ResourcesClusterListener) OnTensorSecret(*assets.TensorSecret, assets.Action) error {
	return nil
}

func (cl *ResourcesClusterListener) OnTensorPV(*assets.TensorPV, assets.Action) error {
	return nil
}

func (cl *ResourcesClusterListener) OnTensorPVC(*assets.TensorPVC, assets.Action) error {
	return nil
}

func (cl *ResourcesClusterListener) OnTensorNamespace(namespace *assets.TensorNamespace, action assets.Action) error {
	return nil
}

func (cl *ResourcesClusterListener) OnTensorNode(node *assets.TensorNode, action assets.Action) error {
	return nil
}

func (cl *ResourcesClusterListener) Name() string {
	return name
}
