package assets

import (
	"context"
	"fmt"
	"strings"
	"time"

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
)

func CountNamespaces(ctx context.Context, rdb *rdbtools.GormWrapper, clusterKey, nameQuery string) (int64, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var nsCount int64
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		db := rdb.Get().WithContext(oneCtx).Model(&model.TensorNamespace{}).Where("status = ? AND cluster_key = ?", 0, clusterKey)
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
	whereCondition map[string]interface{}
	columnQuery    colQuery
}

func ResourcesQuery() *ResourcesQueryOption {
	return &ResourcesQueryOption{
		whereCondition: make(map[string]interface{}, 3),
	}
}

func (q *ResourcesQueryOption) GetClusterOption() (string, bool) {
	v, ok := q.whereCondition["cluster_key"]
	return v.(string), ok
}

func (q *ResourcesQueryOption) WithCluster(clusterKey string) *ResourcesQueryOption {
	q.whereCondition["cluster_key"] = clusterKey
	return q
}
func (q *ResourcesQueryOption) WithNamespace(ns string) *ResourcesQueryOption {
	q.whereCondition["namespace"] = ns
	return q
}
func (q *ResourcesQueryOption) WithResourceKind(kind ResourceKind) *ResourcesQueryOption {
	q.whereCondition["kind"] = kind
	return q
}
func (q *ResourcesQueryOption) WithResourceName(name string) *ResourcesQueryOption {
	q.whereCondition["name"] = name
	return q
}
func (q *ResourcesQueryOption) WithColumnQuery(column, query string) *ResourcesQueryOption {
	q.columnQuery.column = column
	q.columnQuery.query = query
	return q
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
		if len(query.whereCondition) > 0 {
			db = db.Where(query.whereCondition)
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
		if len(query.whereCondition) > 0 {
			db = db.Where(query.whereCondition)
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
	whereCondition map[string]interface{}
	columnQuery    colQuery
}

func ResourceContainersQuery() *ResContainersQueryOption {
	return &ResContainersQueryOption{
		whereCondition: make(map[string]interface{}, 3),
	}
}

func (q *ResContainersQueryOption) GetClusterOption() (string, bool) {
	v, ok := q.whereCondition["cluster_key"]
	return v.(string), ok
}
func (q *ResContainersQueryOption) WithCluster(clusterKey string) *ResContainersQueryOption {
	q.whereCondition["cluster_key"] = clusterKey
	return q
}
func (q *ResContainersQueryOption) WithNamespace(ns string) *ResContainersQueryOption {
	q.whereCondition["namespace"] = ns
	return q
}
func (q *ResContainersQueryOption) WithResourceKind(kind ResourceKind) *ResContainersQueryOption {
	q.whereCondition["resource_kind"] = kind
	return q
}
func (q *ResContainersQueryOption) WithResourceName(name string) *ResContainersQueryOption {
	q.whereCondition["resource_name"] = name
	return q
}
func (q *ResContainersQueryOption) WithContainerName(cname string) *ResContainersQueryOption {
	q.whereCondition["name"] = cname
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

		db := rdb.Get().WithContext(oneCtx).Model(&model.TensorContainer{}).Where("status = ?", 0).Where(query.whereCondition)
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

		db := rdb.Get().WithContext(oneCtx).Model(&model.TensorContainer{}).Where("status = ?", 0).Where(query.whereCondition)
		if limit > 0 && offset >= 0 {
			db = db.Offset(offset).Limit(limit)
		}
		if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
			db = db.Debug().Where(fmt.Sprintf("%s ILIKE ?", query.columnQuery.column), getLikeExpr(query.columnQuery.query))
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
func SoftDeleteResource(ctx context.Context, rdb *rdbtools.GormWrapper, resource *TensorResource, updateTime time.Time) error {
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

func newModelFromTensorResource(resource *TensorResource, updateTime time.Time) *model.TensorResource {
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
func UpsertResource(ctx context.Context, rdb *rdbtools.GormWrapper, resource *TensorResource, updateTime time.Time) (*model.TensorResource, error) {
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

func fromContainerToModel(container corev1.Container, resource *TensorResource, updateTime time.Time) *model.TensorContainer {
	contModel := new(model.TensorContainer)
	contModel.ID = util.GenerateUUID(resource.Cluster, resource.Namespace, string(resource.Kind), resource.Name, container.Name)
	contModel.Name = container.Name
	contModel.ClusterKey = resource.Cluster
	contModel.Namespace = resource.Namespace
	contModel.ResourceKind = string(resource.Kind)
	contModel.ResourceName = resource.Name
	contModel.Image = container.Image
	contModel.ImagePullPolicy = container.ImagePullPolicy
	contModel.Ports = container.Ports
	contModel.SecurityContext = (*model.SecurityContext)(container.SecurityContext)

	contModel.CreatedAt = resource.CreateTime
	contModel.UpdatedAt = updateTime
	contModel.Status = 0
	return contModel
}

func newModelContainersFromResource(resource *TensorResource, updateTime time.Time) []*model.TensorContainer {
	if resource.PodTemplate == nil {
		return nil
	}
	containerNum := len(resource.PodTemplate.Spec.Containers) + len(resource.PodTemplate.Spec.InitContainers)
	containers := make([]*model.TensorContainer, 0, containerNum)

	for _, initCon := range resource.PodTemplate.Spec.InitContainers {
		containers = append(containers,
			fromContainerToModel(initCon, resource, updateTime),
		)
	}
	for _, con := range resource.PodTemplate.Spec.Containers {
		containers = append(containers,
			fromContainerToModel(con, resource, updateTime),
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
func doUpsertResourceContainers(ctx context.Context, rdb *gorm.DB, resource *TensorResource, updateTime time.Time) ([]*model.TensorContainer, error) {
	contModels := newModelContainersFromResource(resource, updateTime)

	for _, contModel := range contModels {
		err := upsertOneContainer(ctx, rdb, contModel)
		if err != nil {
			return nil, err
		}
	}

	// remove containers that are no longer configured by resources
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

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

func CleanUpUnUpdatedResources(ctx context.Context, rdb *rdbtools.GormWrapper, ts time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()

		return rdb.Get().WithContext(oneCtx).Model(&model.TensorResource{}).Where("updated_at < ? AND status = ?", ts, 0).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": ts,
		}).Error
	})
}

func CleanUpUnUpdatedResourceContainers(ctx context.Context, rdb *rdbtools.GormWrapper, ts time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()

		return rdb.Get().WithContext(oneCtx).Model(&model.TensorContainer{}).Where("updated_at < ? AND status = ?", ts, 0).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": ts,
		}).Error
	})
}

func doSoftDeleteResourceContainers(ctx context.Context, rdb *gorm.DB, resource *TensorResource, updateTime time.Time) error {
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

func CleanUpUnUpdatedNamespaces(ctx context.Context, rdb *rdbtools.GormWrapper, ts time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
		defer cancel()

		now := time.Now()
		return rdb.Get().WithContext(oneCtx).Model(&model.TensorNamespace{}).Where("updated_at < ? AND status = ?", ts, 0).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": now,
		}).Error
	})
}
