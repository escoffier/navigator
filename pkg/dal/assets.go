package dal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	corev1 "k8s.io/api/core/v1"
)

var (
	onDupUpdatedColsForContainer = []string{
		"updated_at",
		"status",
		"image",
		"ports",
		"image_pull_policy",
		"security_context",
		"image_uuid",
	}
	onDupUpdatedColsForResource = []string{
		"updated_at",
		"status",
		"label_selector",
		"owner_references",
		"labels",
		"pod_template",
	}
	onDupUpdatedColsForNamespace = []string{
		"owner_references",
		"labels",
		"updated_at",
		"status",
	}
	onDupUpdatedColsForPodResRel = []string{
		"status",
		"updated_at",
		"pod_ip",
		"host_ip",
	}
)

func CountNamespaces(ctx context.Context, rdb *rdbtools.GormWrapper, clusterKey, nameQuery string) (int64, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var nsCount int64
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		db := rdb.Get().WithContext(oneCtx).Model(&model.TensorNamespace{}).Where("status = ?", 0)

		if clusterKey != "" {
			db.Where("cluster_key = ?", clusterKey)
		}
		if nameQuery != "" {
			db = db.Where("name ILIKE ?", getLikeExpr(nameQuery))
		}

		return db.Count(&nsCount).Error
	})
	if err != nil {
		return 0, err
	}
	return nsCount, nil
}

func UpdateNamespace(ctx context.Context, rdb *rdbtools.GormWrapper, clusterKey, name, alias string, managers model.Managers, authority string) error {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		mgs, err := managers.Value()
		if err != nil {
			return err
		}
		data := map[string]interface{}{
			"alias":     alias,
			"managers":  mgs,
			"authority": authority,
		}
		return rdb.Get().WithContext(oneCtx).Model(&model.TensorNamespace{}).
			Where("cluster_key = ? and name = ?", clusterKey, name).Updates(data).Error
	})
	return err
}

func GetNamespacesByCluster(ctx context.Context, rdb *rdbtools.GormWrapper, clusterKey, nameQuery string, offset, limit int) ([]*model.TensorNamespace, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var namespaces []*model.TensorNamespace
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		db := rdb.Get().WithContext(oneCtx).Model(&model.TensorNamespace{}).Where("status = ? AND cluster_key = ?", 0, clusterKey)
		if limit > 0 && offset >= 0 {
			db = db.Offset(offset).Limit(limit)
		}
		if nameQuery != "" {
			db = db.Debug().Where("name ILIKE ?", getLikeExpr(nameQuery))
		}
		return db.Order("id ASC").Find(&namespaces).Error
	})
	if err != nil {
		return nil, err
	}
	return namespaces, nil
}

type colQuery struct {
	column string
	query  string
}
type ResourcesQueryOption struct {
	whereEqCondition map[string]interface{}
	whereInCondition map[string]interface{}
	columnQuery      colQuery
}

func ResourcesQuery() *ResourcesQueryOption {
	return &ResourcesQueryOption{
		whereEqCondition: make(map[string]interface{}, 3),
		whereInCondition: make(map[string]interface{}, 2),
	}
}

func (q *ResourcesQueryOption) GetClusterOption() (string, bool) {
	v, ok := q.whereEqCondition["cluster_key"]
	return v.(string), ok
}

func (q *ResourcesQueryOption) WithCluster(clusterKey string) *ResourcesQueryOption {
	q.whereEqCondition["cluster_key"] = clusterKey
	return q
}
func (q *ResourcesQueryOption) WithNamespace(ns string) *ResourcesQueryOption {
	q.whereEqCondition["namespace"] = ns
	return q
}
func (q *ResourcesQueryOption) WithResourceKind(kind assets.ResourceKind) *ResourcesQueryOption {
	q.whereEqCondition["kind"] = kind
	return q
}
func (q *ResourcesQueryOption) WithCustom(column string, value interface{}) *ResourcesQueryOption {
	q.whereEqCondition[column] = value
	return q
}
func (q *ResourcesQueryOption) WithInConditionCustom(column string, value interface{}) *ResourcesQueryOption {
	q.whereInCondition[column] = value
	return q
}
func (q *ResourcesQueryOption) WithResourceName(name string) *ResourcesQueryOption {
	q.whereEqCondition["name"] = name
	return q
}
func (q *ResourcesQueryOption) WithColumnQuery(column, query string) *ResourcesQueryOption {
	q.columnQuery.column = column
	q.columnQuery.query = query
	return q
}

type ResourceKey struct {
	ClusterKey   string
	Namespace    string
	ResourceKind string
	ResourceName string
}

func getLikeExpr(s string) string {
	sb := strings.Builder{}
	sb.WriteByte('%')
	sb.WriteString(s)
	sb.WriteByte('%')
	return sb.String()
}

func CountResources(ctx context.Context, rdb *rdbtools.GormWrapper, query *ResourcesQueryOption) (int64, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var resCount int64
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		db := rdb.Get().WithContext(oneCtx).Model(&model.TensorResource{}).Where("status = ?", 0)
		if len(query.whereEqCondition) > 0 {
			db = db.Where(query.whereEqCondition)
		}
		if len(query.whereInCondition) > 0 {
			for column, val := range query.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
			db = db.Debug().Where(fmt.Sprintf("%s ILIKE ?", query.columnQuery.column), getLikeExpr(query.columnQuery.query))
		}

		return db.Count(&resCount).Error
	})
	if err != nil {
		return 0, err
	}
	return resCount, nil
}

func GetResources(ctx context.Context, rdb *rdbtools.GormWrapper, query *ResourcesQueryOption, offset, limit int) (resources []*model.TensorResource, err error) {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	err = util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		db := rdb.Get().WithContext(oneCtx).Model(&model.TensorResource{}).Where("status = ?", 0)
		if len(query.whereEqCondition) > 0 {
			db = db.Where(query.whereEqCondition)
		}
		if len(query.whereInCondition) > 0 {
			for column, val := range query.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
			db = db.Debug().Where(fmt.Sprintf("%s ILIKE ?", query.columnQuery.column), getLikeExpr(query.columnQuery.query))
		}
		if limit > 0 && offset >= 0 {
			db = db.Offset(offset).Limit(limit)
		}

		return db.Order("id ASC").Find(&resources).Error
	})
	if err != nil {
		return nil, err
	}
	return resources, nil
}

type ResContainersQueryOption struct {
	whereEqCondition map[string]interface{}
	whereInCondition map[string]interface{}
	columnQuery      colQuery
}

func ResourceContainersQuery() *ResContainersQueryOption {
	return &ResContainersQueryOption{
		whereEqCondition: make(map[string]interface{}, 3),
		whereInCondition: make(map[string]interface{}, 2),
	}
}

func (q *ResContainersQueryOption) GetClusterOption() (string, bool) {
	v, ok := q.whereEqCondition["cluster_key"]
	if !ok {
		return "", false
	}
	return v.(string), ok
}
func (q *ResContainersQueryOption) WithCluster(clusterKey string) *ResContainersQueryOption {
	q.whereEqCondition["cluster_key"] = clusterKey
	return q
}
func (q *ResContainersQueryOption) WithNamespace(ns string) *ResContainersQueryOption {
	q.whereEqCondition["namespace"] = ns
	return q
}
func (q *ResContainersQueryOption) WithResourceKind(kind assets.ResourceKind) *ResContainersQueryOption {
	q.whereEqCondition["resource_kind"] = kind
	return q
}
func (q *ResContainersQueryOption) WithResourceName(name string) *ResContainersQueryOption {
	q.whereEqCondition["resource_name"] = name
	return q
}
func (q *ResContainersQueryOption) WithContainerName(cname string) *ResContainersQueryOption {
	q.whereEqCondition["name"] = cname
	return q
}
func (q *ResContainersQueryOption) WithCustom(column string, value interface{}) *ResContainersQueryOption {
	q.whereEqCondition[column] = value
	return q
}
func (q *ResContainersQueryOption) WithInConditionCustom(column string, value interface{}) *ResContainersQueryOption {
	q.whereInCondition[column] = value
	return q
}
func (q *ResContainersQueryOption) WithColumnQuery(column, query string) *ResContainersQueryOption {
	q.columnQuery.column = column
	q.columnQuery.query = query
	return q
}

func CountResourceContainers(ctx context.Context, rdb *rdbtools.GormWrapper, query *ResContainersQueryOption) (int64, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		db := rdb.Get().WithContext(oneCtx).Model(&model.TensorContainer{}).Where("status = ?", 0)
		if len(query.whereEqCondition) > 0 {
			db = db.Where(query.whereEqCondition)
		}
		if len(query.whereInCondition) > 0 {
			for column, val := range query.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
			db = db.Debug().Where(fmt.Sprintf("%s ILIKE ?", query.columnQuery.column), getLikeExpr(query.columnQuery.query))
		}
		return db.Count(&cntNum).Error
	})
	if err != nil {
		return 0, err
	}
	return cntNum, nil
}
func GetResourceContainers(ctx context.Context, rdb *rdbtools.GormWrapper, query *ResContainersQueryOption, offset, limit int) (containers []*model.TensorContainer, err error) {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	err = util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		db := rdb.Get().WithContext(oneCtx).Model(&model.TensorContainer{}).Where("status = ?", 0)
		if len(query.whereEqCondition) > 0 {
			db = db.Where(query.whereEqCondition)
		}
		if len(query.whereInCondition) > 0 {
			for column, val := range query.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
			db = db.Debug().Where(fmt.Sprintf("%s ILIKE ?", query.columnQuery.column), getLikeExpr(query.columnQuery.query))
		}
		if limit > 0 && offset >= 0 {
			db = db.Offset(offset).Limit(limit)
		}
		return db.Order("id ASC").Find(&containers).Error
	})
	if err != nil {
		return nil, err
	}
	return containers, nil
}

func getResourceUUID(clusterKey, namespace, kind, name string) uint32 {
	return util.GenerateUUID(clusterKey, namespace, kind, name)
}

func doSoftDeleteResource(ctx context.Context, db *gorm.DB, uuid uint32, updateTime time.Time) error {
	pgCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	err := db.WithContext(pgCtx).Model(&model.TensorResource{}).Where("id = ?", uuid).Updates(map[string]interface{}{
		"status":     1,
		"updated_at": updateTime,
	}).Error
	return err
}

// SoftDeleteResource will delete the resources and related containers using transactions.
func SoftDeleteResource(ctx context.Context, rdb *rdbtools.GormWrapper, resource *assets.TensorResource, updateTime time.Time) error {
	uuid := getResourceUUID(resource.Cluster, resource.Namespace, string(resource.Kind), resource.Name)

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	return rdb.Get().WithContext(ctx).Transaction(func(db *gorm.DB) error {
		err := doSoftDeleteResource(ctx, db, uuid, updateTime)
		if err != nil {
			return err
		}
		// delete releted containers
		return doSoftDeleteResourceContainers(ctx, db, resource, updateTime)
	})
}

func newModelFromTensorResource(resource *assets.TensorResource, updateTime time.Time) *model.TensorResource {
	m := new(model.TensorResource)
	m.ID = getResourceUUID(resource.Cluster, resource.Namespace, string(resource.Kind), resource.Name)
	m.Name = resource.Name
	m.Namespace = resource.Namespace
	m.ClusterKey = resource.Cluster
	m.UID = resource.UID
	m.Kind = string(resource.Kind)
	if resource.LabelSelector != nil {
		m.LabelSelector = new(model.LabelSelector)
		m.LabelSelector.MatchLabels = resource.LabelSelector.MatchLabels
		m.LabelSelector.MatchExpressions = resource.LabelSelector.MatchExpressions
	}
	if len(resource.OwnerReferences) > 0 {
		m.OwnerReferences = make(model.OwnerRefs, len(resource.OwnerReferences))
		for i, oref := range resource.OwnerReferences {
			m.OwnerReferences[i].Kind = oref.Kind
			m.OwnerReferences[i].Name = oref.Name
		}
	}

	if resource.Labels != nil {
		m.Labels = make(model.Labels, len(resource.Labels))
		for key, value := range resource.Labels {
			m.Labels[key] = value
		}
	}

	if resource.PodTemplate != nil {
		m.PodTemplate = new(model.PodTemplate)
		m.PodTemplate.InitContainers = resource.PodTemplate.Spec.InitContainers
		m.PodTemplate.Containers = resource.PodTemplate.Spec.Containers
		m.PodTemplate.ServiceAccountName = resource.PodTemplate.Spec.ServiceAccountName
		m.PodTemplate.NodeName = resource.PodTemplate.Spec.NodeName
		m.PodTemplate.HostNetwork = resource.PodTemplate.Spec.HostNetwork
		m.PodTemplate.HostPID = resource.PodTemplate.Spec.HostPID
		m.PodTemplate.HostIPC = resource.PodTemplate.Spec.HostIPC
		m.PodTemplate.ImagePullSecrets = make([]string, len(resource.PodTemplate.Spec.ImagePullSecrets))
		for i, sec := range resource.PodTemplate.Spec.ImagePullSecrets {
			m.PodTemplate.ImagePullSecrets[i] = sec.Name
		}
		m.PodTemplate.PodSecurityContext = resource.PodTemplate.Spec.SecurityContext
	}
	m.CreatedAt = resource.CreateTime
	m.UpdatedAt = updateTime
	m.Status = 0

	return m
}

func doUpsertResource(ctx context.Context, rdb *gorm.DB, resourceModel *model.TensorResource, updateTime time.Time) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()
	return rdb.WithContext(oneCtx).Model(&model.TensorResource{}).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForResource),
	}).Create(resourceModel).Error
}

// UpsertResource will update tensor_resources and also tensor_containers using transactions. One fail will cause the whole update rollback.
func UpsertResource(ctx context.Context, rdb *rdbtools.GormWrapper, resource *assets.TensorResource, updateTime time.Time) (*model.TensorResource, error) {
	resourceModel := newModelFromTensorResource(resource, updateTime)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err := rdb.Get().WithContext(ctx).Transaction(func(db *gorm.DB) error {
		err := doUpsertResource(ctx, db, resourceModel, updateTime)
		if err != nil {
			return err
		}
		_, err = doUpsertResourceContainers(ctx, db, resource, updateTime)
		return err
	})

	return resourceModel, err
}

func UpdateResourceUserData(ctx context.Context, rdb *rdbtools.GormWrapper, resource *model.TensorResource) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	managers, err := resource.Managers.Value()
	if err != nil {
		return err
	}
	data := map[string]interface{}{
		"alias":     resource.Alias,
		"managers":  managers,
		"authority": resource.Authority,
	}
	return rdb.Get().WithContext(oneCtx).Model(&model.TensorResource{}).
		Where("cluster_key = ? and namespace = ? and kind = ? and name = ?", resource.ClusterKey, resource.Namespace, resource.Kind, resource.Name).
		Updates(data).Error
}

func fromContainerToModel(container corev1.Container, resource *assets.TensorResource, updateTime time.Time, conType string) *model.TensorContainer {
	contModel := new(model.TensorContainer)
	contModel.ID = util.GenerateUUID(resource.Cluster, resource.Namespace, string(resource.Kind), resource.Name, container.Name)
	contModel.Name = container.Name
	contModel.ClusterKey = resource.Cluster
	contModel.Namespace = resource.Namespace
	contModel.ResourceKind = string(resource.Kind)
	contModel.ResourceName = resource.Name
	contModel.Image = container.Image
	contModel.ImagePullPolicy = container.ImagePullPolicy
	contModel.ImageUUID = util.GenerateUUID(container.Image)
	contModel.Ports = container.Ports
	contModel.SecurityContext = (*model.SecurityContext)(container.SecurityContext)
	contModel.Spec = (*model.ContainerSpec)(&container)
	contModel.Type = conType

	contModel.CreatedAt = resource.CreateTime
	contModel.UpdatedAt = updateTime
	contModel.Status = 0
	return contModel
}

func newModelContainersFromResource(resource *assets.TensorResource, updateTime time.Time) []*model.TensorContainer {
	if resource.PodTemplate == nil {
		return nil
	}
	containerNum := len(resource.PodTemplate.Spec.Containers) + len(resource.PodTemplate.Spec.InitContainers)
	containers := make([]*model.TensorContainer, 0, containerNum)

	for _, initCon := range resource.PodTemplate.Spec.InitContainers {
		containers = append(containers,
			fromContainerToModel(initCon, resource, updateTime, "InitContainer"),
		)
	}
	for _, con := range resource.PodTemplate.Spec.Containers {
		containers = append(containers,
			fromContainerToModel(con, resource, updateTime, "Container"),
		)
	}
	return containers
}
func upsertOneContainer(ctx context.Context, rdb *gorm.DB, containerModel *model.TensorContainer) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()
	err := rdb.WithContext(oneCtx).Model(&model.TensorContainer{}).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForContainer),
	}).Create(containerModel).Error
	if err != nil {
		return err
	}
	return nil
}
func doUpsertResourceContainers(ctx context.Context, rdb *gorm.DB, resource *assets.TensorResource, updateTime time.Time) ([]*model.TensorContainer, error) {
	contModels := newModelContainersFromResource(resource, updateTime)

	for _, contModel := range contModels {
		err := upsertOneContainer(ctx, rdb, contModel)
		if err != nil {
			return nil, err
		}
	}

	// remove containers that are no longer configured by resources

	existingUUIDs := make([]uint32, len(contModels))
	for i, cont := range contModels {
		existingUUIDs[i] = cont.ID
	}

	oneCtx, oneCancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer oneCancel()

	err := rdb.WithContext(oneCtx).Model(&model.TensorContainer{}).Where("cluster_key = ? AND namespace = ? AND resource_kind = ? AND resource_name = ?",
		resource.Cluster, resource.Namespace, resource.Kind, resource.Name).Where("id not in ?", existingUUIDs).Updates(map[string]interface{}{
		"status":     1,
		"updated_at": updateTime,
	}).Error
	if err != nil {
		return nil, err
	}

	return contModels, nil
}

func CleanUpUnUpdatedResources(ctx context.Context, rdb *rdbtools.GormWrapper, ts time.Time, clusterKey string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()

		return rdb.Get().WithContext(oneCtx).Model(&model.TensorResource{}).Where("updated_at < ? AND status = ? AND cluster_key = ?", ts, 0, clusterKey).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": ts,
		}).Error
	})
}

func CleanUpUnUpdatedResourceContainers(ctx context.Context, rdb *rdbtools.GormWrapper, ts time.Time, clusterKey string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()

		return rdb.Get().WithContext(oneCtx).Model(&model.TensorContainer{}).Where("updated_at < ? AND status = ? AND cluster_key = ?", ts, 0, clusterKey).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": ts,
		}).Error
	})
}

func doSoftDeleteResourceContainers(ctx context.Context, rdb *gorm.DB, resource *assets.TensorResource, updateTime time.Time) error {
	if resource.PodTemplate == nil {
		return nil
	}

	uuids := make([]uint32, 0, 3)
	for _, c := range resource.PodTemplate.Spec.InitContainers {
		uuid := util.GenerateUUID(resource.Cluster, resource.Namespace, string(resource.Kind), resource.Name, c.Name)
		uuids = append(uuids, uuid)
	}
	for _, c := range resource.PodTemplate.Spec.Containers {
		uuid := util.GenerateUUID(resource.Cluster, resource.Namespace, string(resource.Kind), resource.Name, c.Name)
		uuids = append(uuids, uuid)
	}

	oneCtx, oneCancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer oneCancel()

	return rdb.WithContext(oneCtx).Model(&model.TensorContainer{}).Where("id in ?", uuids).Updates(map[string]interface{}{
		"status":     1,
		"updated_at": updateTime,
	}).Error
}

func fromNamespaceToModel(ns *corev1.Namespace, clusterKey string, updateTime time.Time) *model.TensorNamespace {
	nsModel := new(model.TensorNamespace)
	nsModel.ID = util.GenerateUUID(clusterKey, ns.Name)
	nsModel.Name = ns.Name
	nsModel.UID = string(ns.UID)
	nsModel.ClusterKey = clusterKey

	if len(ns.OwnerReferences) > 0 {
		nsModel.OwnerReferences = make(model.OwnerRefs, len(ns.OwnerReferences))
		for i, oref := range ns.OwnerReferences {
			nsModel.OwnerReferences[i].Kind = oref.Kind
			nsModel.OwnerReferences[i].Name = oref.Name
		}
	}

	if nsModel.Labels != nil {
		nsModel.Labels = make(model.Labels, len(ns.Labels))
		for key, value := range ns.Labels {
			nsModel.Labels[key] = value
		}
	}

	nsModel.CreatedAt = ns.CreationTimestamp.Time
	nsModel.UpdatedAt = updateTime
	nsModel.Status = 0

	return nsModel
}

func UpsertNamespace(ctx context.Context, rdb *rdbtools.GormWrapper, ns *corev1.Namespace, clusterKey string, updateTime time.Time) (*model.TensorNamespace, error) {
	nsModel := fromNamespaceToModel(ns, clusterKey, updateTime)

	oneCtx, oneCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer oneCancel()
	err := rdb.Get().WithContext(oneCtx).Model(nsModel).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForNamespace),
	}).Create(nsModel).Error

	return nsModel, err
}

func SoftDeleteNamespace(ctx context.Context, rdb *rdbtools.GormWrapper, ns *corev1.Namespace, clusterkey string, updateTime time.Time) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer oneCancel()

	id := util.GenerateUUID(clusterkey, ns.Name)
	return rdb.Get().WithContext(oneCtx).Model(&model.TensorNamespace{}).Where("id = ? AND status = ?", id, 0).Updates(map[string]interface{}{
		"status":     1,
		"updated_at": updateTime,
	}).Error
}

func CleanUpUnUpdatedNamespaces(ctx context.Context, rdb *rdbtools.GormWrapper, ts time.Time, clusterKey string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
		defer cancel()

		now := time.Now()
		return rdb.Get().WithContext(oneCtx).Model(&model.TensorNamespace{}).Where("updated_at < ? AND status = ? AND cluster_key = ?", ts, 0, clusterKey).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": now,
		}).Error
	})
}

func getRedisKeyForPodResRelByName(clusterKey, namespace, podName string) string {
	return fmt.Sprintf("podname-res-rel:%s/%s/%s", clusterKey, namespace, podName)
}
func getRedisKeyForPodResRelByPodIP(clusterKey, podIP string) string {
	return fmt.Sprintf("podip-res-rel:%s/%s", clusterKey, podIP)
}
func getRedisKeyForPodResRelByUID(clusterKey, podUID string) string {
	return fmt.Sprintf("poduid-res-rel:%s/%s", clusterKey, podUID)
}
func getRedisKeyForResourceControlled(clusterKey, namespace, kind, name string) string {
	return fmt.Sprintf("res-controlled:%s/%s/%s/%s", clusterKey, namespace, kind, name)
}

type prqKind string

const (
	podIP   prqKind = "podIP"
	podUID  prqKind = "podUID"
	podName prqKind = "podName"
)

type PodResRelationQuery struct {
	kind   prqKind
	value  string
	value2 string
}

func (q *PodResRelationQuery) WithPodIP(ip string) *PodResRelationQuery {
	q.kind = podIP
	q.value = ip
	return q
}
func (q *PodResRelationQuery) WithPodUID(uid string) *PodResRelationQuery {
	q.kind = podUID
	q.value = uid
	return q
}
func (q *PodResRelationQuery) WithPodName(name, namespace string) *PodResRelationQuery {
	q.kind = podName
	q.value = name
	q.value2 = namespace
	return q
}

func GetPodResourceRelation(ctx context.Context, redisCli *redis.Client, clusterKey string, query *PodResRelationQuery) (*model.PodResourceRelation, bool, error) {
	var rkey string
	switch query.kind {
	case podIP:
		rkey = getRedisKeyForPodResRelByPodIP(clusterKey, query.value)
	case podUID:
		rkey = getRedisKeyForPodResRelByUID(clusterKey, query.value)
	case podName:
		rkey = getRedisKeyForPodResRelByName(clusterKey, query.value2, query.value)
	default:
		return nil, false, errors.New("illegal queryKind")
	}

	rctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()
	val := ""
	rerr := util.RetryWithBackoff(rctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rctx, 200*time.Millisecond)
		defer oneCancel()

		res, err := redisCli.Get(oneCtx, rkey).Result()
		if err != nil {
			if err == redis.Nil {
				return nil
			}
			return err
		}
		val = res
		return nil
	})
	if rerr != nil {
		return nil, false, rerr
	}

	if val == "" {
		return nil, false, nil
	}
	var r model.PodResourceRelation
	jerr := json.Unmarshal([]byte(val), &r)
	if jerr != nil {
		return nil, false, jerr
	}
	return &r, true, nil
}

func UpsertPodResourceRelationInRDB(ctx context.Context, rdb *rdbtools.GormWrapper, pod *corev1.Pod, resourceName, resKind, clusterKey string, updateTime time.Time) error {
	rel := model.PodResourceRelation{
		ClusterKey:   clusterKey,
		Namespace:    pod.GetNamespace(),
		PodName:      pod.GetName(),
		ResourceName: resourceName,
		ResourceKind: resKind,
		PodUID:       string(pod.GetUID()),
		PodIP:        pod.Status.PodIP,
		HostIP:       pod.Status.HostIP,
		NodeName:     pod.Spec.NodeName,
	}
	rel.CreatedAt = pod.GetCreationTimestamp().Time
	rel.UpdatedAt = updateTime
	rel.ID = util.GenerateUUID(clusterKey, rel.Namespace, rel.ResourceKind, rel.ResourceName, rel.PodUID)

	rCtx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 300*time.Millisecond)
		defer oneCancel()
		return rdb.Get().WithContext(oneCtx).Model(&rel).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForPodResRel),
		}).Create(&rel).Error
	})
}

func DeletePodResourceRelationInRDB(ctx context.Context, rdb *rdbtools.GormWrapper, pod *corev1.Pod, clusterKey string) error {
	rCtx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 300*time.Millisecond)
		defer oneCancel()
		return rdb.Get().WithContext(oneCtx).Where("cluster_key = ? AND pod_uid = ?", clusterKey, string(pod.GetUID())).Delete(&model.PodResourceRelation{}).Error
	})
}

func CleanUpPodResourceRelationsInRDB(ctx context.Context, rdb *rdbtools.GormWrapper, ts time.Time, clusterKey string) error {
	rCtx, cancel := context.WithTimeout(ctx, 15000*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 5000*time.Millisecond)
		defer oneCancel()
		return rdb.Get().WithContext(oneCtx).Where("updated_at < ? AND cluster_key = ?", ts, clusterKey).Delete(&model.PodResourceRelation{}).Error
	})
}

func UpsertPodResourceRelation(ctx context.Context, redisCli *redis.Client, pod *corev1.Pod, resourceName, resKind, clusterKey string, ttl time.Duration) error {
	rel := model.PodResourceRelation{
		ClusterKey:      clusterKey,
		Namespace:       pod.GetNamespace(),
		PodName:         pod.GetName(),
		ResourceName:    resourceName,
		ResourceKind:    resKind,
		PodUID:          string(pod.GetUID()),
		PodIP:           pod.Status.PodIP,
		HostIP:          pod.Status.HostIP,
		CreateTimestamp: pod.GetCreationTimestamp().Unix(),
	}

	relBytes, err := json.Marshal(rel)
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(rctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rctx, 300*time.Millisecond)
		defer oneCancel()
		pipe := redisCli.Pipeline()

		relStr := string(relBytes)
		pipe.Set(oneCtx, getRedisKeyForPodResRelByName(clusterKey, pod.GetNamespace(), pod.GetName()), relStr, ttl)
		if rel.PodIP != "" {
			pipe.Set(oneCtx, getRedisKeyForPodResRelByPodIP(clusterKey, rel.PodIP), relStr, ttl)
		}
		pipe.Set(oneCtx, getRedisKeyForPodResRelByUID(clusterKey, rel.PodUID), relStr, ttl)
		// pipe.SAdd(ctx, getRedisKeyForResourceControlled(clusterKey, rel.Namespace, resKind, resourceName), rel.PodUID)
		_, err := pipe.Exec(oneCtx)
		return err
	})
}

func DeletePodResourceRelation(ctx context.Context, redisCli *redis.Client, pod *corev1.Pod, clusterKey string) error {
	rctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(rctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rctx, 200*time.Millisecond)
		defer oneCancel()
		pipe := redisCli.Pipeline()
		pipe.Del(oneCtx, getRedisKeyForPodResRelByName(clusterKey, pod.GetNamespace(), pod.GetName()))
		if pod.Status.PodIP != "" {
			pipe.Del(oneCtx, getRedisKeyForPodResRelByPodIP(clusterKey, pod.Status.PodIP))
		}
		pipe.Del(oneCtx, getRedisKeyForPodResRelByUID(clusterKey, string(pod.GetUID())))
		// pipe.SRem(oneCtx, getRedisKeyForResourceControlled(clusterKey, pod.GetNamespace(), resKind, resourceName), string(pod.GetUID()))
		_, err := pipe.Exec(oneCtx)
		return err
	})
}

type ResPodsQueryOption struct {
	whereEqCondition map[string]interface{}
	whereInCondition map[string]interface{}
	columnQuery      colQuery
}

func ResourcePodssQuery() *ResPodsQueryOption {
	return &ResPodsQueryOption{
		whereEqCondition: make(map[string]interface{}, 3),
		whereInCondition: make(map[string]interface{}, 2),
	}
}

func (q *ResPodsQueryOption) GetClusterOption() (string, bool) {
	v, ok := q.whereEqCondition["cluster_key"]
	if !ok {
		return "", false
	}
	return v.(string), ok
}
func (q *ResPodsQueryOption) WithCluster(clusterKey string) *ResPodsQueryOption {
	q.whereEqCondition["cluster_key"] = clusterKey
	return q
}
func (q *ResPodsQueryOption) WithNamespace(ns string) *ResPodsQueryOption {
	q.whereEqCondition["namespace"] = ns
	return q
}
func (q *ResPodsQueryOption) WithResourceKind(kind assets.ResourceKind) *ResPodsQueryOption {
	q.whereEqCondition["resource_kind"] = kind
	return q
}
func (q *ResPodsQueryOption) WithResourceName(name string) *ResPodsQueryOption {
	q.whereEqCondition["resource_name"] = name
	return q
}
func (q *ResPodsQueryOption) WithContainerName(cname string) *ResPodsQueryOption {
	q.whereEqCondition["name"] = cname
	return q
}
func (q *ResPodsQueryOption) WithCustom(column string, value interface{}) *ResPodsQueryOption {
	q.whereEqCondition[column] = value
	return q
}
func (q *ResPodsQueryOption) WithInConditionCustom(column string, value interface{}) *ResPodsQueryOption {
	q.whereInCondition[column] = value
	return q
}
func (q *ResPodsQueryOption) WithColumnQuery(column, query string) *ResPodsQueryOption {
	q.columnQuery.column = column
	q.columnQuery.query = query
	return q
}

func GetResourcePodsList(ctx context.Context, rdb *rdbtools.GormWrapper, queryOptions *ResPodsQueryOption, offset, limit int) ([]*model.PodResourceRelation, error) {
	rctx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
	defer cancel()

	var rels []*model.PodResourceRelation
	notFound := false
	err := util.RetryWithBackoff(rctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rctx, 500*time.Millisecond)
		defer oneCancel()

		db := rdb.Get().WithContext(oneCtx).Model(&model.PodResourceRelation{}).Where("status = ?", 0)
		if len(queryOptions.whereEqCondition) > 0 {
			db.Where(queryOptions.whereEqCondition)
		}

		if len(queryOptions.whereInCondition) > 0 {
			for column, val := range queryOptions.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
			db = db.Debug().Where(fmt.Sprintf("%s ILIKE ?", queryOptions.columnQuery.column), getLikeExpr(queryOptions.columnQuery.query))
		}

		if offset >= 0 && limit >= 0 {
			db.Offset(offset).Limit(limit)
		}

		err := db.Find(&rels).Error
		if err == gorm.ErrRecordNotFound {
			notFound = true
			return nil
		}
		return err
	})
	if notFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rels, nil
}

func CountPods(ctx context.Context, rdb *rdbtools.GormWrapper, queryOptions *ResPodsQueryOption) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		db := rdb.Get().WithContext(oneCtx).Model(&model.PodResourceRelation{}).Where("status = ?", 0)
		if len(queryOptions.whereEqCondition) > 0 {
			db = db.Where(queryOptions.whereEqCondition)
		}
		if len(queryOptions.whereInCondition) > 0 {
			for column, val := range queryOptions.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
			db = db.Debug().Where(fmt.Sprintf("%s ILIKE ?", queryOptions.columnQuery.column), getLikeExpr(queryOptions.columnQuery.query))
		}

		return db.Count(&cntNum).Error
	})

	return cntNum, err
}

func GetClusters(ctx context.Context, rdb *rdbtools.GormWrapper, offset, limit int) (clusters []*model.TensorCluster, totalCnt int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	err = util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		oneErr := rdb.Get().WithContext(oneCtx).Model(&model.TensorCluster{}).Where("status = ?", 0).Order("key").Offset(offset).Limit(limit).Find(&clusters).Error
		if oneErr != nil {
			return oneErr
		}
		return rdb.Get().WithContext(ctx).Model(&model.TensorCluster{}).Where("status = ?", 0).Count(&totalCnt).Error
	})
	return
}
func GetClustersByKey(ctx context.Context, rdb *rdbtools.GormWrapper, key string) *model.TensorCluster {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()
	var cluster model.TensorCluster
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		return rdb.Get().WithContext(oneCtx).Model(&model.TensorCluster{}).Where("status = ? AND key = ?", 0, key).First(&cluster).Error

	})
	if err != nil {
		return nil
	}

	return &cluster
}
func UpdateCluster(ctx context.Context, rdb *rdbtools.GormWrapper, clusterKey string, name string, description string) error {
	if clusterKey == "" {
		return errors.New("illegal argument")
	}
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	userInfo, ok := util.GetUserFromContext(ctx)
	updateMap := map[string]interface{}{
		"name":        name,
		"description": description,
		"updated_at":  time.Now(),
	}
	if ok {
		updateMap["updater"] = userInfo.UserName
	}

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		return rdb.Get().WithContext(oneCtx).Model(&model.TensorCluster{}).Where("key = ? AND status = ?", clusterKey, 0).Updates(updateMap).Error
	})
}
func AddCluster(ctx context.Context, rdb *rdbtools.GormWrapper, cluster *model.TensorCluster) error {
	if cluster == nil || cluster.Key == "" {
		return errors.New("illegal argument")
	}
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	userInfo, ok := util.GetUserFromContext(ctx)
	if ok {
		cluster.Creator = userInfo.UserName
		cluster.Updater = userInfo.UserName
	}
	cluster.CreatedAt = time.Now()
	cluster.UpdatedAt = cluster.CreatedAt

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		return rdb.Get().WithContext(oneCtx).Model(&model.TensorCluster{}).Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "key"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"certificate_auth_data",
				"secret_token",
				"status",
				"cluster_type",
				"worker_namespace",
			}),
		}).Create(cluster).Error
	})
}

func DeleteCluster(ctx context.Context, rdb *rdbtools.GormWrapper, clusterKey string) error {
	if clusterKey == "" {
		return errors.New("illegal argument")
	}
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()
		return rdb.Get().WithContext(oneCtx).Delete(&model.TensorCluster{}, clusterKey).Error
	})
}

func CountCluster(ctx context.Context, rdb *rdbtools.GormWrapper) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()
	var count int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()
		return rdb.Get().WithContext(oneCtx).Count(&count).Error
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}
