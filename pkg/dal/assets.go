package dal

import (
	"context"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	json "github.com/json-iterator/go"
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
		"type",
		"image_uuid",
		"app_type",
		"app_target_version",
		"app_target_name",
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
		"node_name",
		"pod_container_infos",
	}
	OnDupUpdatedColsForNodes = []string{
		"host_name",
		"node_ip",
		"kernel_version",
		"os_info",
		"container_runtime_version",
		"kubelet_version",
		"kube_proxy_version",
		"architecture",
		"os_image",
		"volumes",
		"container_images",
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

func GetNamespace(ctx context.Context, rdb *rdbtools.GormWrapper, clusterKey, name string) (*model.TensorNamespace, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var namespace model.TensorNamespace
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		return rdb.Get().WithContext(oneCtx).Model(&model.TensorNamespace{}).
			Where("status = ? AND cluster_key = ? AND name = ?", 0, clusterKey, name).First(&namespace).Error
	})
	if err != nil {
		return nil, err
	}
	return &namespace, nil
}

type colQuery struct {
	column string
	query  string
}

type mulColQuery struct {
	columns []string
	query   string
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
		oneCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
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
	whereEqCondition      map[string]interface{}
	whereNotNullCondition map[string]struct{}
	whereInCondition      map[string]interface{}
	columnQuery           colQuery
}

func ResourceContainersQuery() *ResContainersQueryOption {
	return &ResContainersQueryOption{
		whereEqCondition:      make(map[string]interface{}, 3),
		whereInCondition:      make(map[string]interface{}, 2),
		whereNotNullCondition: make(map[string]struct{}, 2),
	}
}

func (q *ResContainersQueryOption) GetClusterOption() (string, bool) {
	v, ok := q.whereEqCondition["cluster_key"]
	if !ok {
		return "", false
	}
	return v.(string), ok
}

func (q *ResContainersQueryOption) WithAppType(appType string) *ResContainersQueryOption {
	q.whereEqCondition["app_type"] = appType
	return q
}
func (q *ResContainersQueryOption) WithAppTypeNotEmpty() *ResContainersQueryOption {
	q.whereNotNullCondition["app_type"] = struct{}{}
	return q
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
		if len(query.whereNotNullCondition) > 0 {
			for column, _ := range query.whereNotNullCondition {
				db = db.Where(fmt.Sprintf("%s IS NOT NULL", column))
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
		oneCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
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
		if len(query.whereNotNullCondition) > 0 {
			for column, _ := range query.whereNotNullCondition {
				db = db.Where(fmt.Sprintf("%s IS NOT NULL", column))
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

	isWebFrame, webType, version, err := model.GetWebType(contModel.Image)
	if err == nil && isWebFrame {
		contModel.AppType = &model.AppTypeWeb
		contModel.AppTargetName = &webType
		contModel.AppTargetVersion = &version

	} else {
		isDB, dbType, version, err := model.GetDatabaseType(contModel.Image)
		if err == nil && isDB {
			contModel.AppType = &model.AppTypeDB
			contModel.AppTargetName = &dbType
			contModel.AppTargetVersion = &version
		}
	}

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

	if ns.Labels != nil {
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

	rctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	val := ""
	rerr := util.RetryWithBackoff(rctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rctx, 400*time.Millisecond)
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
	podContainerInfos := &model.PodContainerInfos{
		InitContainerInfo: nil,
		ContainerInfo:     nil,
	}
	for i := range pod.Status.InitContainerStatuses {
		podContainerInfos.InitContainerInfo = append(podContainerInfos.InitContainerInfo, model.PodContainerInfo{
			ImageID:     pod.Status.InitContainerStatuses[i].ContainerID,
			ContainerID: pod.Status.InitContainerStatuses[i].ImageID,
		})
	}

	for i := range pod.Status.ContainerStatuses {
		podContainerInfos.ContainerInfo = append(podContainerInfos.ContainerInfo, model.PodContainerInfo{
			ImageID:     pod.Status.ContainerStatuses[i].ContainerID,
			ContainerID: pod.Status.ContainerStatuses[i].ImageID,
		})
	}
	logging.GetLogger().Info().Msgf("%+v", pod.Status)
	logging.GetLogger().Info().Msgf("%+v", *podContainerInfos)
	rel := model.PodResourceRelation{
		ClusterKey:        clusterKey,
		Namespace:         pod.GetNamespace(),
		PodName:           pod.GetName(),
		ResourceName:      resourceName,
		ResourceKind:      resKind,
		PodUID:            string(pod.GetUID()),
		PodIP:             pod.Status.PodIP,
		HostIP:            pod.Status.HostIP,
		NodeName:          pod.Spec.NodeName,
		PodContainerInfos: podContainerInfos,
	}
	rel.CreatedAt = pod.GetCreationTimestamp().Time
	rel.UpdatedAt = updateTime
	rel.ID = util.GenerateUUID(clusterKey, rel.Namespace, rel.ResourceKind, rel.ResourceName, rel.PodUID)

	rCtx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 500*time.Millisecond)
		defer oneCancel()
		return rdb.Get().WithContext(oneCtx).Model(&rel).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForPodResRel),
		}).Create(&rel).Error
	})
}

func DeletePodResourceRelationInRDB(ctx context.Context, rdb *rdbtools.GormWrapper, pod *corev1.Pod, clusterKey string) error {
	rCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 500*time.Millisecond)
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
		_, err := pipe.Exec(oneCtx)
		return err
	})
}

func DeletePodResourceRelation(ctx context.Context, redisCli *redis.Client, pod *corev1.Pod, clusterKey string) error {
	rctx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
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
	mulColQuery      mulColQuery
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
func (q *ResPodsQueryOption) WithNodeName(nodeName string) *ResPodsQueryOption {
	q.whereEqCondition["node_name"] = nodeName
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

func (q *ResPodsQueryOption) WithMulColumnQuery(column []string, query string) *ResPodsQueryOption {
	q.mulColQuery.columns = column
	q.mulColQuery.query = query
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
			db = db.Debug().Where(queryOptions.whereEqCondition)
		}

		if len(queryOptions.whereInCondition) > 0 {
			for column, val := range queryOptions.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s ILIKE ?", queryOptions.columnQuery.column), getLikeExpr(queryOptions.columnQuery.query))
		}

		if len(queryOptions.mulColQuery.columns) > 0 && len(queryOptions.mulColQuery.query) > 0 {
			expr := getLikeExpr(queryOptions.mulColQuery.query)
			db = db.Where(
				rdb.Get().WithContext(oneCtx).Model(&model.PodResourceRelation{}).Where("pod_name ILIKE ?", expr).Or("pod_ip ILIKE ?", expr).Or("node_name ILIKE ?", expr))
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

func CountPods(ctx context.Context, rdb *rdbtools.GormWrapper, queryOptions *ResPodsQueryOption, offset, limit int) (int64, error) {
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

		if len(queryOptions.mulColQuery.columns) > 0 && len(queryOptions.mulColQuery.query) > 0 {
			expr := getLikeExpr(queryOptions.mulColQuery.query)
			db = db.Where(
				rdb.Get().WithContext(oneCtx).Model(&model.PodResourceRelation{}).Where("pod_name ILIKE ?", expr).Or("pod_ip ILIKE ?", expr).Or("node_name ILIKE ?", expr))
		}
		if offset >= 0 && limit >= 0 {
			db.Offset(offset).Limit(limit)
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

	userInfo, ok := util.GetSessionFromContext(ctx)
	updateMap := map[string]interface{}{
		"name":        name,
		"description": description,
		"updated_at":  time.Now(),
	}
	if ok {
		updateMap["updater"] = userInfo.Username
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

	userInfo, ok := util.GetSessionFromContext(ctx)
	if ok {
		cluster.Creator = userInfo.Username
		cluster.Updater = userInfo.Username
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

func newModelFromNode(node *corev1.Node, clusterKey string, updateTime time.Time) (*model.TensorNode, error) {
	n := new(model.TensorNode)
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			n.NodeIP = addr.Address
		} else if addr.Type == corev1.NodeHostName {
			n.HostName = addr.Address
		}
	}
	if n.HostName == "" {
		return nil, errors.New("missing significant nodeIPs/hostNames")
	}
	n.ID = util.GenerateUUID(clusterKey, n.HostName)
	n.ClusterKey = clusterKey
	n.Architecture = node.Status.NodeInfo.Architecture
	n.ContainerRuntimeVersion = node.Status.NodeInfo.ContainerRuntimeVersion
	n.CreatedAt = updateTime
	n.UpdatedAt = updateTime
	n.KernelVersion = node.Status.NodeInfo.KernelVersion
	n.OsInfo = node.Status.NodeInfo.OperatingSystem
	n.OsImage = node.Status.NodeInfo.OSImage
	n.KubeProxyVersion = node.Status.NodeInfo.KubeProxyVersion
	n.KubeletVersion = node.Status.NodeInfo.KubeletVersion
	n.Volumes = make([]model.NodeVolume, 0, len(node.Status.VolumesAttached)+len(node.Status.VolumesInUse))
	for _, v := range node.Status.VolumesAttached {
		n.Volumes = append(n.Volumes, model.NodeVolume{
			Type:       "attached",
			VolumeName: string(v.Name),
			DevicePath: v.DevicePath,
		})
	}
	for _, v := range node.Status.VolumesInUse {
		n.Volumes = append(n.Volumes, model.NodeVolume{
			Type:       "in_use",
			VolumeName: string(v),
		})
	}
	n.ContainerImages = node.Status.Images
	switch node.Status.Phase {
	case corev1.NodeRunning:
		n.Status = 0
	case corev1.NodeTerminated:
		n.Status = 1
	case corev1.NodePending:
		n.Status = 2
	}

	return n, nil
}

func SoftDeleteNode(ctx context.Context, rdb *gorm.DB, node *corev1.Node, clusterKey string, updateTime time.Time) error {
	hostName := ""
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeHostName {
			hostName = addr.Address
			break
		}
	}
	if hostName == "" {
		return errors.New("error input")
	}
	tctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	uuid := util.GenerateUUID(clusterKey, hostName)
	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(tctx, 700*time.Millisecond)
		defer cancel()
		return rdb.WithContext(oneCtx).Model(&model.TensorNode{}).Where("id = ?", uuid).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": updateTime,
		}).Error
	})
}
func UpsertNode(ctx context.Context, rdb *gorm.DB, node *corev1.Node, clusterKey string, updateTime time.Time) (uint32, error) {
	n, createErr := newModelFromNode(node, clusterKey, updateTime)
	if createErr != nil {
		return 0, createErr
	}

	tctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(tctx, 700*time.Millisecond)
		defer cancel()
		return rdb.WithContext(oneCtx).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns(OnDupUpdatedColsForNodes),
		}).Create(n).Error
	})
	return n.ID, err
}

func CleanUpUnUpdatedNodes(ctx context.Context, rdb *gorm.DB, clusterKey string, t time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
		defer cancel()

		return rdb.WithContext(oneCtx).Model(&model.TensorNode{}).Where("updated_at < ? AND status = ? AND cluster_key = ?", t, 0, clusterKey).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": t,
		}).Error
	})
}

type NodeQueryOption struct {
	whereEqCondition map[string]interface{}
	whereInCondition map[string]interface{}
	columnQuery      colQuery
}

func NodeQuery() *NodeQueryOption {
	return &NodeQueryOption{
		whereEqCondition: make(map[string]interface{}, 3),
		whereInCondition: make(map[string]interface{}, 2),
	}
}

func (q *NodeQueryOption) GetClusterOption() (string, bool) {
	v, ok := q.whereEqCondition["cluster_key"]
	if !ok {
		return "", false
	}
	return v.(string), ok
}
func (q *NodeQueryOption) WithCluster(clusterKey string) *NodeQueryOption {
	q.whereEqCondition["cluster_key"] = clusterKey
	return q
}
func (q *NodeQueryOption) WithCustom(column string, value interface{}) *NodeQueryOption {
	q.whereEqCondition[column] = value
	return q
}
func (q *NodeQueryOption) WithStatus(status int8) *NodeQueryOption {
	q.whereEqCondition["status"] = status
	return q
}
func (q *NodeQueryOption) WithInConditionCustom(column string, value interface{}) *NodeQueryOption {
	q.whereInCondition[column] = value
	return q
}
func (q *NodeQueryOption) WithColumnQuery(column, query string) *NodeQueryOption {
	q.columnQuery.column = column
	q.columnQuery.query = query
	return q
}

func GetNodes(ctx context.Context, rdb *gorm.DB, queryOptions *NodeQueryOption, offset, limit int) ([]*model.TensorNode, error) {
	rctx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
	defer cancel()

	var nodes []*model.TensorNode
	notFound := false
	err := util.RetryWithBackoff(rctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rctx, 500*time.Millisecond)
		defer oneCancel()

		db := rdb.WithContext(oneCtx).Model(&model.TensorNode{}).Order("id asc")
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

		err := db.Find(&nodes).Error
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
	return nodes, nil
}

func CountNodes(ctx context.Context, rdb *gorm.DB, queryOptions *NodeQueryOption) (int64, error) {
	rctx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
	defer cancel()

	var count int64
	notFound := false
	err := util.RetryWithBackoff(rctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rctx, 500*time.Millisecond)
		defer oneCancel()

		db := rdb.WithContext(oneCtx).Model(&model.TensorNode{})
		if len(queryOptions.whereEqCondition) > 0 {
			db.Where(queryOptions.whereEqCondition)
		}

		if len(queryOptions.whereInCondition) > 0 {
			for column, val := range queryOptions.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s ILIKE ?", queryOptions.columnQuery.column), getLikeExpr(queryOptions.columnQuery.query))
		}

		err := db.Count(&count).Error
		if err == gorm.ErrRecordNotFound {
			notFound = true
			return nil
		}
		return err
	})
	if notFound {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return count, nil
}

func GetFramework(ctx context.Context, rdb *gorm.DB, imageid uint32) (*model.WebFrameScan, error) {
	rctx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
	defer cancel()

	var frm model.WebFrameScan
	notFound := false
	err := util.RetryWithBackoff(rctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rctx, 500*time.Millisecond)
		defer oneCancel()

		db := rdb.WithContext(oneCtx).Model(&model.WebFrameScan{})
		db.Where("image_uuid = ?", imageid)
		err := db.First(&frm).Error
		if err == gorm.ErrRecordNotFound {
			notFound = true
			return nil
		}
		return err

	})
	if notFound {
		return nil, nil
	}
	return &frm, err
}

func GetFrameworks(ctx context.Context, rdb *gorm.DB) ([]*model.WebFrameScan, error) {
	rctx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
	defer cancel()

	var frms []*model.WebFrameScan
	err := util.RetryWithBackoff(rctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rctx, 500*time.Millisecond)
		defer oneCancel()

		db := rdb.WithContext(oneCtx).Model(&model.WebFrameScan{})
		return db.Find(&frms).Error
	})
	return frms, err
}
