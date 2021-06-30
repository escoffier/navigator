package microseg

import (
	"context"
	"errors"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	model "gitlab.com/tensorsecurity-rd/go-pkg/model"
	"gorm.io/gorm/clause"
	corev1 "k8s.io/api/core/v1"
)

const (
	name = "microseg_resources_listener"
)

type ResourcesListener struct {
	rdb *rdbtools.GormWrapper
}

func NewResourcesListener(rdb *rdbtools.GormWrapper) *ResourcesListener {
	return &ResourcesListener{
		rdb: rdb,
	}
}
func (rl *ResourcesListener) BeforWatchNewCluster(ctx context.Context, clusterName string) assets.ClusterCallback {
	return &ResourcesClusterListener{
		parent: rl,
		stTime: time.Now(),
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
	parent *ResourcesListener
	stTime time.Time
}

func (cl *ResourcesClusterListener) OnPodEvent(newPod, oldPod *corev1.Pod, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *ResourcesClusterListener) OnEndPointEvent(newEpt, oldEpt *corev1.Endpoints, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *ResourcesClusterListener) OnServiceEvent(newSvc, oldEvc *corev1.Service, action assets.AssetsAction) error {
	// do nothing
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

func shouldResourceBeFiltered(res *assets.TensorResource) bool {
	if res.Kind != assets.KindReplicaSet {
		return false
	}
	return len(res.OwnerReferences) > 0 && res.OwnerReferences[0].Kind == string(assets.KindDeployment)
}

func (cl *ResourcesClusterListener) OnTensorResourceEvent(newResource, oldResource *assets.TensorResource, action assets.AssetsAction) error {

	switch action {
	case assets.ActionAdd, assets.ActionUpdate:
		if newResource == nil {
			return errors.New("nil resource")
		}

		// Because we have watched the changes of Deployments, the replicasets that are controlled by a Deployment will be ignored
		if shouldResourceBeFiltered(newResource) {
			return nil
		}
		err := cl.upsertMicrosegResource(context.Background(), newResource)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("ResourcesClusterListener upsert resource error. res: %+v", newResource)
			return err
		}
	case assets.ActionDelete:
		if oldResource == nil {
			return errors.New("nil resource")
		}

		// Because we have watched the changes of Deployments, the replicasets that are controlled by a Deployment will be ignored
		if shouldResourceBeFiltered(oldResource) {
			return nil
		}
		err := cl.removeMicrosegResource(context.Background(), oldResource)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("ResourcesClusterListener remove resource error. res: %+v", oldResource)
			return err
		}
	}
	return nil
}
func (cl *ResourcesClusterListener) AfterDataSynced(ctx context.Context, dataSynced bool) {
	if !dataSynced {
		return
	}

	db := cl.parent.rdb.Get()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(context.Background(), 3000*time.Millisecond)
		defer oneCancel()

		return db.WithContext(oneCtx).Model(&model.TensorMicrosegResource{}).Where("updated_at < ? AND status = 0", cl.stTime).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": time.Now(),
		}).Error
	})
	if err != nil {
		logging.GetLogger().Err(err).Msg("data synced. update databases error")
	}

}
func (cl *ResourcesClusterListener) Name() string {
	return name
}
