package dal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	ContainerTypeInit    = "InitContainer"
	ContainerTypeDefault = "Container"
	running              = 0
	terminated           = 1
	waiting              = 2
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
		"spec",
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
		// "volumes",
		// "container_images",
		"updated_at",
		"status",
		"ready",
	}
)

func CountNamespaces(ctx context.Context, rdb *gorm.DB, clusterKey, nameQuery string) (int64, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var nsCount int64
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.TensorNamespace{}).Where("status = ?", 0)

		if clusterKey != "" {
			db.Where("cluster_key = ?", clusterKey)
		}
		if nameQuery != "" {
			db = db.Where("name LIKE ?", getLikeExpr(nameQuery))
		}

		return db.Count(&nsCount).Error
	})
	if err != nil {
		return 0, err
	}
	return nsCount, nil
}

func UpdateNamespace(ctx context.Context, rdb *gorm.DB, clusterKey, name, alias string, managers model.Managers, authority string) error {
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
		return rdb.WithContext(oneCtx).Model(&model.TensorNamespace{}).
			Where("cluster_key = ? and name = ?", clusterKey, name).Updates(data).Error
	})
	return err
}

func GetNamespacesByCluster(ctx context.Context, rdb *gorm.DB, clusterKey, nameQuery string, offset, limit int) ([]*model.TensorNamespace, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var namespaces []*model.TensorNamespace
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.TensorNamespace{}).Where("status = ? AND cluster_key = ?", 0, clusterKey)
		if limit > 0 && offset >= 0 {
			db = db.Offset(offset).Limit(limit)
		}
		if nameQuery != "" {
			db = db.Where("name LIKE ?", getLikeExpr(nameQuery))
		}
		return db.Order("id ASC").Find(&namespaces).Error
	})
	if err != nil {
		return nil, err
	}
	return namespaces, nil
}

func GetNamespace(ctx context.Context, rdb *gorm.DB, clusterKey, name string) (*model.TensorNamespace, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var namespace model.TensorNamespace
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		return rdb.WithContext(oneCtx).Model(&model.TensorNamespace{}).
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

func (q *ResourcesQueryOption) WithID(id uint32) *ResourcesQueryOption {
	q.whereEqCondition["id"] = id
	return q
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

func CountResources(ctx context.Context, rdb *gorm.DB, query *ResourcesQueryOption) (int64, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var resCount int64
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.TensorResource{}).Where("status = ?", 0)
		if len(query.whereEqCondition) > 0 {
			db = db.Where(query.whereEqCondition)
		}
		if len(query.whereInCondition) > 0 {
			for column, val := range query.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), getLikeExpr(query.columnQuery.query))
		}
		return db.Count(&resCount).Error
	})
	if err != nil {
		return 0, err
	}
	return resCount, nil
}

func GetResources(ctx context.Context, rdb *gorm.DB, query *ResourcesQueryOption, offset, limit int) (resources []*model.TensorResource, err error) {
	pgCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err = util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.TensorResource{}).Where("status = ?", 0)
		if len(query.whereEqCondition) > 0 {
			db = db.Where(query.whereEqCondition)
		}
		if len(query.whereInCondition) > 0 {
			for column, val := range query.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), getLikeExpr(query.columnQuery.query))
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
	WhereEqCondition      map[string]interface{}
	whereNotNullCondition map[string]struct{}
	whereInCondition      map[string]interface{}
	columnQuery           colQuery
}

func ResourceContainersQuery() *ResContainersQueryOption {
	return &ResContainersQueryOption{
		WhereEqCondition:      make(map[string]interface{}, 3),
		whereInCondition:      make(map[string]interface{}, 2),
		whereNotNullCondition: make(map[string]struct{}, 2),
	}
}

func (q *ResContainersQueryOption) GetClusterOption() (string, bool) {
	v, ok := q.WhereEqCondition["cluster_key"]
	if !ok {
		return "", false
	}
	return v.(string), ok
}

func (q *ResContainersQueryOption) WithAppType(appType string) *ResContainersQueryOption {
	q.WhereEqCondition["app_type"] = appType
	return q
}
func (q *ResContainersQueryOption) WithAppTypeNotEmpty() *ResContainersQueryOption {
	q.whereNotNullCondition["app_type"] = struct{}{}
	return q
}
func (q *ResContainersQueryOption) WithCluster(clusterKey string) *ResContainersQueryOption {
	q.WhereEqCondition["cluster_key"] = clusterKey
	return q
}
func (q *ResContainersQueryOption) WithNamespace(ns string) *ResContainersQueryOption {
	q.WhereEqCondition["namespace"] = ns
	return q
}
func (q *ResContainersQueryOption) WithResourceKind(kind assets.ResourceKind) *ResContainersQueryOption {
	q.WhereEqCondition["resource_kind"] = kind
	return q
}
func (q *ResContainersQueryOption) WithResourceName(name string) *ResContainersQueryOption {
	q.WhereEqCondition["resource_name"] = name
	return q
}
func (q *ResContainersQueryOption) WithContainerName(cname string) *ResContainersQueryOption {
	q.WhereEqCondition["name"] = cname
	return q
}
func (q *ResContainersQueryOption) WithCustom(column string, value interface{}) *ResContainersQueryOption {
	q.WhereEqCondition[column] = value
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

func CountResourceContainers(ctx context.Context, rdb *gorm.DB, query *ResContainersQueryOption) (int64, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.TensorContainer{}).Where("status = ?", 0)
		if len(query.WhereEqCondition) > 0 {
			db = db.Where(query.WhereEqCondition)
		}
		if len(query.whereInCondition) > 0 {
			for column, val := range query.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(query.whereNotNullCondition) > 0 {
			for column := range query.whereNotNullCondition {
				db = db.Where(fmt.Sprintf("%s IS NOT NULL", column))
			}
		}
		if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), getLikeExpr(query.columnQuery.query))
		}
		return db.Count(&cntNum).Error
	})
	if err != nil {
		return 0, err
	}
	return cntNum, nil
}
func GetResourceContainers(ctx context.Context, rdb *gorm.DB, query *ResContainersQueryOption, offset, limit int) (containers []*model.TensorContainer, err error) {
	pgCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	err = util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.TensorContainer{}).Where("status = ?", 0)
		if len(query.WhereEqCondition) > 0 {
			db = db.Where(query.WhereEqCondition)
		}
		if len(query.whereInCondition) > 0 {
			for column, val := range query.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(query.whereNotNullCondition) > 0 {
			for column := range query.whereNotNullCondition {
				db = db.Where(fmt.Sprintf("%s IS NOT NULL", column))
			}
		}
		if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), getLikeExpr(query.columnQuery.query))
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

func GetResourceUUID(clusterKey, namespace, kind, name string) uint32 {
	return util.GenerateUUID(clusterKey, namespace, kind, name)
}

func doSoftDeleteResource(ctx context.Context, db *gorm.DB, uuid uint32, updateTime time.Time) error {
	pgCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	err := db.WithContext(pgCtx).Model(&model.TensorResource{}).Where("id = ?", uuid).Updates(map[string]interface{}{
		"status":     1,
		"updated_at": updateTime,
	}).Error
	if err == gorm.ErrRecordNotFound {
		return nil
	}
	return err
}

// SoftDeleteResource will delete the resources and related containers using transactions.
func SoftDeleteResource(ctx context.Context, rdb *gorm.DB, resource *assets.TensorResource, updateTime time.Time) error {
	uuid := GetResourceUUID(resource.Cluster, resource.Namespace, string(resource.Kind), resource.Name)

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	return rdb.WithContext(ctx).Transaction(func(db *gorm.DB) error {
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
	m.ID = GetResourceUUID(resource.Cluster, resource.Namespace, string(resource.Kind), resource.Name)
	m.Name = resource.Name
	m.Namespace = resource.Namespace
	m.ClusterKey = resource.Cluster
	m.UID = string(resource.UID)
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
		var err error
		m.Labels, err = json.Marshal(resource.Labels)
		if err != nil {
			logging.GetLogger().Err(err).Msg(" err occurred whe parsing resource labels")
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
	oneCtx, oneCancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer oneCancel()
	resourceModel.UpdatedAt = updateTime
	return rdb.WithContext(oneCtx).Model(&model.TensorResource{}).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForResource),
	}).Create(resourceModel).Error
}

// UpsertResource will update tensor_resources and also tensor_containers using transactions. One fail will cause the whole update rollback.
func UpsertResource(ctx context.Context, rdb *gorm.DB, resource *assets.TensorResource, updateTime time.Time) (*model.TensorResource, error) {
	resourceModel := newModelFromTensorResource(resource, updateTime)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err := rdb.WithContext(ctx).Transaction(func(db *gorm.DB) error {
		err := doUpsertResource(ctx, db, resourceModel, updateTime)
		if err != nil {
			return err
		}
		_, err = doUpsertResourceContainers(ctx, db, resource, updateTime)
		return err
	})

	return resourceModel, err
}

func UpdateResourceUserData(ctx context.Context, rdb *gorm.DB, resource *model.TensorResource) error {
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
	return rdb.WithContext(oneCtx).Model(&model.TensorResource{}).
		Where("cluster_key = ? and namespace = ? and kind = ? and name = ?", resource.ClusterKey, resource.Namespace, resource.Kind, resource.Name).
		Updates(data).Error
}

func GetContainerUUID(cluster, namespace, kind, resourceName, containerName string) uint32 {
	return util.GenerateUUID(cluster, namespace, string(kind), resourceName, containerName)
}
func fromContainerToModel(ctx context.Context, rdb *gorm.DB, container corev1.Container, resource *assets.TensorResource, updateTime time.Time, conType string) *model.TensorContainer {
	contModel := new(model.TensorContainer)
	contModel.ID = GetContainerUUID(resource.Cluster, resource.Namespace, string(resource.Kind), resource.Name, container.Name)
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

	if conType == ContainerTypeDefault {
		isWebFrame, webType, version, err := model.GetAppType(contModel.Image, model.WebMatcher)
		if err == nil && isWebFrame {
			contModel.AppType = &model.AppTypeWeb
			contModel.AppTargetName = &webType
			contModel.AppTargetVersion = &version

		} else {
			isDB, dbType, version, err := model.GetAppType(contModel.Image, model.DBMatcher)
			if err == nil && isDB {
				contModel.AppType = &model.AppTypeDB
				contModel.AppTargetName = &dbType
				contModel.AppTargetVersion = &version
			}
		}

		//TODO: may be removed later
		webFrameScan, err := GetFramework(ctx, rdb, contModel.ImageUUID)
		if err == nil && webFrameScan != nil {
			var infos []model.WebFrameInfo
			err = json.Unmarshal(webFrameScan.WebFrameInfoJSON, &infos)
			if err == nil {
				contModel.AppType = &model.AppTypeWeb
				if len(infos) > 0 {
					contModel.AppTargetName = &infos[0].FrameName
					contModel.AppTargetVersion = &infos[0].Version
				}
			}
		}
	}

	return contModel
}

func newModelContainersFromResource(ctx context.Context, rdb *gorm.DB, resource *assets.TensorResource, updateTime time.Time) []*model.TensorContainer {
	if resource.PodTemplate == nil {
		return nil
	}
	containerNum := len(resource.PodTemplate.Spec.Containers) + len(resource.PodTemplate.Spec.InitContainers)
	containers := make([]*model.TensorContainer, 0, containerNum)

	for _, initCon := range resource.PodTemplate.Spec.InitContainers {
		containers = append(containers,
			fromContainerToModel(ctx, rdb, initCon, resource, updateTime, ContainerTypeInit),
		)
	}
	for _, con := range resource.PodTemplate.Spec.Containers {
		containers = append(containers,
			fromContainerToModel(ctx, rdb, con, resource, updateTime, ContainerTypeDefault),
		)
	}
	return containers
}
func upsertOneContainer(ctx context.Context, rdb *gorm.DB, containerModel *model.TensorContainer) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 1000*time.Millisecond)
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
	contModels := newModelContainersFromResource(ctx, rdb, resource, updateTime)

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

func CleanUpUnUpdatedResources(ctx context.Context, rdb *gorm.DB, ts time.Time, clusterKey string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()

		return rdb.WithContext(oneCtx).Model(&model.TensorResource{}).Where("updated_at < ? AND status = ? AND cluster_key = ?", ts, 0, clusterKey).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": ts,
		}).Error
	})
}

func CleanUpUnUpdatedResourceContainers(ctx context.Context, rdb *gorm.DB, ts time.Time, clusterKey string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()

		return rdb.WithContext(oneCtx).Model(&model.TensorContainer{}).Where("updated_at < ? AND status = ? AND cluster_key = ?", ts, 0, clusterKey).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": ts,
		}).Error
	})
}

func doSoftDeleteResourceContainers(ctx context.Context, rdb *gorm.DB, resource *assets.TensorResource, updateTime time.Time) error {
	//if resource.PodTemplate == nil {
	//	return nil
	//}
	//
	//uuids := make([]uint32, 0, 3)
	//for _, c := range resource.PodTemplate.Spec.InitContainers {
	//	uuid := util.GenerateUUID(resource.Cluster, resource.Namespace, string(resource.Kind), resource.Name, c.Name)
	//	uuids = append(uuids, uuid)
	//}
	//for _, c := range resource.PodTemplate.Spec.Containers {
	//	uuid := util.GenerateUUID(resource.Cluster, resource.Namespace, string(resource.Kind), resource.Name, c.Name)
	//	uuids = append(uuids, uuid)
	//}
	//
	//oneCtx, oneCancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	//defer oneCancel()
	//
	//err := rdb.WithContext(oneCtx).Model(&model.TensorContainer{}).Where("id in ?", uuids).Updates(map[string]interface{}{
	//	"status":     1,
	//	"updated_at": updateTime,
	//}).Error

	oneCtx, oneCancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer oneCancel()
	err := rdb.WithContext(oneCtx).Model(&model.TensorContainer{}).
		Where("cluster_key = ?  AND namespace = ? AND resource_kind = ? AND resource_name = ?",
			resource.Cluster, resource.Namespace, resource.Kind, resource.Name).
		Updates(map[string]interface{}{
			"status":     1,
			"updated_at": updateTime,
		}).Error
	if err == gorm.ErrRecordNotFound {
		return nil
	}
	return err
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
		nsModel.Labels, _ = json.Marshal(ns.Labels)
		//nsModel.Labels = make(model.Labels, len(ns.Labels))
		//for key, value := range ns.Labels {
		//	nsModel.Labels[key] = value
		//}
	}

	nsModel.CreatedAt = ns.CreationTimestamp.Time
	nsModel.UpdatedAt = updateTime
	nsModel.Status = 0

	return nsModel
}

func UpsertNamespace(ctx context.Context, rdb *gorm.DB, ns *corev1.Namespace, clusterKey string, updateTime time.Time) (*model.TensorNamespace, error) {
	nsModel := fromNamespaceToModel(ns, clusterKey, updateTime)

	oneCtx, oneCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer oneCancel()
	err := rdb.WithContext(oneCtx).Model(nsModel).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForNamespace),
	}).Create(nsModel).Error

	return nsModel, err
}

func SoftDeleteNamespace(ctx context.Context, rdb *gorm.DB, ns *corev1.Namespace, clusterKey string, updateTime time.Time) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer oneCancel()

	id := util.GenerateUUID(clusterKey, ns.Name)
	return rdb.WithContext(oneCtx).Model(&model.TensorNamespace{}).Where("id = ? AND status = ?", id, 0).Updates(map[string]interface{}{
		"status":     1,
		"updated_at": updateTime,
	}).Error
}

func CleanUpUnUpdatedNamespaces(ctx context.Context, rdb *gorm.DB, ts time.Time, clusterKey string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
		defer cancel()

		now := time.Now()
		return rdb.WithContext(oneCtx).Model(&model.TensorNamespace{}).Where("updated_at < ? AND status = ? AND cluster_key = ?", ts, 0, clusterKey).Updates(map[string]interface{}{
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

func GetPodInfoFromK8sClient(ctx context.Context, k8sCli *kubernetes.Clientset, namespace, podName string) (*corev1.Pod, error) {
	return k8sCli.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
}

func UpsertPodResourceRelationInRDB(ctx context.Context, rdb *gorm.DB, pod *corev1.Pod, resourceName, resKind, clusterKey string, updateTime time.Time) error {
	podContainerInfos := &model.PodContainerInfos{
		InitContainerInfo: nil,
		ContainerInfo:     nil,
	}
	for i := range pod.Status.InitContainerStatuses {
		podContainerInfos.InitContainerInfo = append(podContainerInfos.InitContainerInfo, model.PodContainerInfo{
			ImageID:     pod.Status.InitContainerStatuses[i].ImageID,
			ContainerID: pod.Status.InitContainerStatuses[i].ContainerID,
		})
	}

	for i := range pod.Status.ContainerStatuses {
		podContainerInfos.ContainerInfo = append(podContainerInfos.ContainerInfo, model.PodContainerInfo{
			ImageID:     pod.Status.ContainerStatuses[i].ImageID,
			ContainerID: pod.Status.ContainerStatuses[i].ContainerID,
		})
	}

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

	rCtx, cancel := context.WithTimeout(ctx, 5000*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 1000*time.Millisecond)
		defer oneCancel()
		return rdb.WithContext(oneCtx).Model(&rel).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForPodResRel),
		}).Create(&rel).Error
	})
}

func DeletePodResourceRelationInRDB(ctx context.Context, rdb *gorm.DB, clusterKey, namespace, name string) error {
	rCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 500*time.Millisecond)
		defer oneCancel()

		err := rdb.WithContext(oneCtx).
			Where("cluster_key = ? AND namespace = ? AND pod_name= ?", clusterKey, namespace, name).
			Delete(&model.PodResourceRelation{}).Error
		if err != gorm.ErrRecordNotFound {
			return nil
		}
		return err
	})
}

func CleanUpPodResourceRelationsInRDB(ctx context.Context, rdb *gorm.DB, ts time.Time, clusterKey string) error {
	rCtx, cancel := context.WithTimeout(ctx, 15000*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 5000*time.Millisecond)
		defer oneCancel()
		return rdb.WithContext(oneCtx).Where("updated_at < ? AND cluster_key = ?", ts, clusterKey).Delete(&model.PodResourceRelation{}).Error
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

func GetResourcePodsList(ctx context.Context, rdb *gorm.DB, queryOptions *ResPodsQueryOption, offset, limit int) ([]*model.PodResourceRelation, error) {
	rctx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
	defer cancel()

	var rels []*model.PodResourceRelation
	notFound := false
	err := util.RetryWithBackoff(rctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rctx, 500*time.Millisecond)
		defer oneCancel()

		db := rdb.WithContext(oneCtx).Model(&model.PodResourceRelation{}).Where("status = ?", 0)
		if len(queryOptions.whereEqCondition) > 0 {
			db = db.Where(queryOptions.whereEqCondition)
		}

		if len(queryOptions.whereInCondition) > 0 {
			for column, val := range queryOptions.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.columnQuery.column), getLikeExpr(queryOptions.columnQuery.query))
		}

		if len(queryOptions.mulColQuery.columns) > 0 && len(queryOptions.mulColQuery.query) > 0 {
			expr := getLikeExpr(queryOptions.mulColQuery.query)
			db = db.Where(
				rdb.WithContext(oneCtx).Model(&model.PodResourceRelation{}).Where("pod_name LIKE ?", expr).
					Or("pod_ip LIKE ?", expr).Or("node_name LIKE ?", expr))
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

func CountPods(ctx context.Context, rdb *gorm.DB, queryOptions *ResPodsQueryOption, offset, limit int) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		db := rdb.WithContext(oneCtx).Model(&model.PodResourceRelation{}).Where("status = ?", 0)
		if len(queryOptions.whereEqCondition) > 0 {
			db = db.Where(queryOptions.whereEqCondition)
		}
		if len(queryOptions.whereInCondition) > 0 {
			for column, val := range queryOptions.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.columnQuery.column), getLikeExpr(queryOptions.columnQuery.query))
		}

		if len(queryOptions.mulColQuery.columns) > 0 && len(queryOptions.mulColQuery.query) > 0 {
			expr := getLikeExpr(queryOptions.mulColQuery.query)
			db = db.Where(
				rdb.WithContext(oneCtx).Model(&model.PodResourceRelation{}).Where("pod_name LIKE ?", expr).Or("pod_ip LIKE ?", expr).Or("node_name LIKE ?", expr))
		}
		if offset >= 0 && limit >= 0 {
			db.Offset(offset).Limit(limit)
		}

		return db.Count(&cntNum).Error
	})

	return cntNum, err
}

func GetClusters(ctx context.Context, rdb *gorm.DB, offset, limit int) (clusters []*model.TensorCluster, totalCnt int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	err = util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		oneErr := rdb.WithContext(oneCtx).Model(&model.TensorCluster{}).Where("status = ?", 0).Order("id").Offset(offset).Limit(limit).Find(&clusters).Error
		if oneErr != nil {
			return oneErr
		}
		return rdb.WithContext(ctx).Model(&model.TensorCluster{}).Where("status = ?", 0).Count(&totalCnt).Error
	})
	return
}
func GetClustersByKey(ctx context.Context, rdb *gorm.DB, key string) *model.TensorCluster {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()
	var cluster model.TensorCluster
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		return rdb.WithContext(oneCtx).Model(&model.TensorCluster{}).Where("status = ? AND id = ?", 0, key).First(&cluster).Error
	})
	if err != nil {
		return nil
	}

	return &cluster
}
func UpdateCluster(ctx context.Context, rdb *gorm.DB, clusterKey string, name string, description string) error {
	if clusterKey == "" {
		return errors.New("illegal argument")
	}
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	userInfo, ok := model.GetSessionFromContext(ctx)
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

		return rdb.WithContext(oneCtx).Model(&model.TensorCluster{}).Where("id = ? AND status = ?", clusterKey, 0).Updates(updateMap).Error
	})
}
func AddCluster(ctx context.Context, rdb *gorm.DB, cluster *model.TensorCluster) error {
	if cluster == nil || cluster.Key == "" {
		return errors.New("illegal argument")
	}
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	userInfo, ok := model.GetSessionFromContext(ctx)
	if ok {
		cluster.Creator = userInfo.Username
		cluster.Updater = userInfo.Username
	}
	cluster.CreatedAt = time.Now()
	cluster.UpdatedAt = cluster.CreatedAt

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		return rdb.WithContext(oneCtx).Model(&model.TensorCluster{}).Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"certificate_auth_data",
				"secret_token",
				"client_cert_data",
				"client_key_data",
				"status",
				"cluster_type",
				"worker_namespace",
				"name",
				"platform",
				"api_server_addr",
				"platform",
				"version",
			}),
		}).Create(cluster).Error
	})
}

func DeleteCluster(ctx context.Context, rdb *gorm.DB, clusterKey string) error {
	if clusterKey == "" {
		return errors.New("illegal argument")
	}
	ctx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 600*time.Millisecond)
		defer oneCancel()
		return rdb.WithContext(oneCtx).Delete(&model.TensorCluster{}, clusterKey).Error
	})
}

func CountCluster(ctx context.Context, rdb *gorm.DB) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()
	var count int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()
		return rdb.WithContext(oneCtx).Count(&count).Error
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

	if assets.NodeIsReady(node) {
		n.Ready = 1
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

func CleanUpUnUpdatedNodes(ctx context.Context, rdb *gorm.DB, t time.Time, clusterKey string) error {
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
			db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.columnQuery.column), getLikeExpr(queryOptions.columnQuery.query))
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

func GetNodesHostAndOS(ctx context.Context, rdb *gorm.DB) ([]*model.TensorNode, error) {
	rCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var nodes []*model.TensorNode
	notFound := false
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 5*time.Second)
		defer oneCancel()

		db := rdb.WithContext(oneCtx).Model(&model.TensorNode{}).Order("id asc")
		err := db.Select("host_name", "os_info").Find(&nodes).Error
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
			db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.columnQuery.column), getLikeExpr(queryOptions.columnQuery.query))
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
	rctx, cancel := context.WithTimeout(ctx, 5000*time.Millisecond)
	defer cancel()

	var frms []*model.WebFrameScan
	err := util.RetryWithBackoff(rctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rctx, 1000*time.Millisecond)
		defer oneCancel()

		db := rdb.WithContext(oneCtx).Model(&model.WebFrameScan{})
		return db.Find(&frms).Error
	})
	return frms, err
}

func CountContainer(ctx context.Context, rdb *gorm.DB, query *ResContainersQueryOption) (int64, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var count int64
	notFound := false
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.TensorContainer{}).Where("status = ?", 0)
		if len(query.WhereEqCondition) > 0 {
			db = db.Where(query.WhereEqCondition)
		}
		if len(query.whereInCondition) > 0 {
			for column, val := range query.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(query.whereNotNullCondition) > 0 {
			for column := range query.whereNotNullCondition {
				db = db.Where(fmt.Sprintf("%s IS NOT NULL", column))
			}
		}
		if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), getLikeExpr(query.columnQuery.query))
		}
		err := db.Distinct("image").Count(&count).Error
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

func GetResourceContainersUnique(ctx context.Context, rdb *gorm.DB, query *ResContainersQueryOption, offset, limit int) (containers []*model.TensorContainer, err error) {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	err = util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.TensorContainer{}).Where("status = ?", 0)
		if len(query.WhereEqCondition) > 0 {
			db = db.Where(query.WhereEqCondition)
		}
		if len(query.whereInCondition) > 0 {
			for column, val := range query.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(query.whereNotNullCondition) > 0 {
			for column := range query.whereNotNullCondition {
				db = db.Where(fmt.Sprintf("%s IS NOT NULL", column))
			}
		}
		if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), getLikeExpr(query.columnQuery.query))
		}
		if limit > 0 && offset >= 0 {
			db = db.Offset(offset).Limit(limit)
		}
		return db.Distinct("image").Find(&containers).Error
	})
	if err != nil {
		return nil, err
	}
	return containers, nil
}

func GetContainerRelation(ctx context.Context, rdb *gorm.DB, query *ResContainersQueryOption, offsetID int64, offset int, limit int) (clusters []*model.TensorContainerRelation, err error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	err = util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()
		if len(query.WhereEqCondition) > 0 {
			rdb = rdb.Where(query.WhereEqCondition)
		}
		if len(query.whereInCondition) > 0 {
			for column, val := range query.whereInCondition {
				rdb = rdb.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(query.whereNotNullCondition) > 0 {
			for column := range query.whereNotNullCondition {
				rdb = rdb.Where(fmt.Sprintf("%s IS NOT NULL", column))
			}
		}
		if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
			rdb = rdb.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), getLikeExpr(query.columnQuery.query))
		}
		if offsetID >= 0 {
			rdb = rdb.Where("time_stamp >= ?", offsetID)
		}
		if offset >= 0 {
			rdb = rdb.Offset(offset)
		}

		return rdb.WithContext(oneCtx).Model(&model.TensorContainerRelation{}).Order("time_stamp").Limit(limit).Find(&clusters).Error
	})
	return
}

func CountContainerRelation(ctx context.Context, rdb *gorm.DB, query *ResContainersQueryOption) (totalCnt int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	err = util.RetryWithBackoff(ctx, func() error {
		if len(query.WhereEqCondition) > 0 {
			rdb = rdb.Where(query.WhereEqCondition)
		}
		if len(query.whereInCondition) > 0 {
			for column, val := range query.whereInCondition {
				rdb = rdb.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(query.whereNotNullCondition) > 0 {
			for column := range query.whereNotNullCondition {
				rdb = rdb.Where(fmt.Sprintf("%s IS NOT NULL", column))
			}
		}
		if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
			rdb = rdb.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), getLikeExpr(query.columnQuery.query))
		}
		return rdb.WithContext(ctx).Model(&model.TensorContainerRelation{}).Count(&totalCnt).Error
	})
	return
}
func genContainer(pod *corev1.Pod, ContainerStatus *corev1.ContainerStatus, resourceName, resKind, clusterKey string, updateTime time.Time) *model.TensorContainerRelation {
	container := &model.TensorContainerRelation{
		ID:            util.GenerateUUID(ContainerStatus.ContainerID),
		Name:          ContainerStatus.Name,
		PodName:       pod.Name,
		ContainerID:   ContainerStatus.ContainerID,
		ClusterKey:    clusterKey,
		Namespace:     pod.Namespace,
		ResourceName:  resourceName,
		ResourceKind:  resKind,
		CreatedAt:     pod.CreationTimestamp.Time,
		UpdatedAt:     updateTime,
		Status:        getContainerStatus(&ContainerStatus.State),
		PodUID:        string(pod.UID),
		PodIP:         pod.Status.PodIP,
		HostIP:        pod.Status.HostIP,
		NodeName:      pod.Spec.NodeName,
		HostNetwork:   pod.Spec.HostNetwork,
		ContainerInfo: &model.ContainerInfos{PodSecurityPolicy: pod.Spec.SecurityContext},
		TimeStamp:     updateTime.UnixMicro(),
	}
	spec, err := getContainerSpec(ContainerStatus.Name, pod)
	if err != nil {
		return container
	}
	library, err := util.GetImageUrl(spec.Image)
	if err == nil {
		container.Library = library
	}
	container.Image = strings.TrimPrefix(spec.Image, library)
	container.Image = strings.TrimPrefix(container.Image, "/")
	container.Environment = spec.Env
	container.Cmd = spec.Command
	container.Arguments = spec.Args
	if spec.SecurityContext != nil && spec.SecurityContext.Privileged != nil {
		container.Privileged = *(spec.SecurityContext.Privileged)
	}
	return container
}

func getContainerSpec(name string, pod *corev1.Pod) (*corev1.Container, error) {
	for i := range pod.Spec.InitContainers {
		if pod.Spec.InitContainers[i].Name == name {
			return pod.Spec.InitContainers[i].DeepCopy(), nil
		}
	}

	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == name {
			return pod.Spec.Containers[i].DeepCopy(), nil
		}
	}
	return nil, fmt.Errorf("not found container: %s", name)
}

func UpsertPodContainerRelation(ctx context.Context, rdb *gorm.DB, pod *corev1.Pod, resourceName, resKind, clusterKey string, updateTime time.Time, poolInfo *assets.PoolInfo) error {
	var cnt_rels []*model.TensorContainerRelation
	for i := range pod.Status.InitContainerStatuses {
		cnt := genContainer(pod, &pod.Status.InitContainerStatuses[i], resourceName, resKind, clusterKey, updateTime)
		if poolInfo != nil {
			cnt.PoolName = poolInfo.PoolName
			cnt.PoolUID = poolInfo.PoolUID
			cnt.PoolPodName = poolInfo.PoolPodName
			cnt.PoolPodUID = poolInfo.PoolPodUID
		}
		cnt_rels = append(cnt_rels, cnt)
	}

	for i := range pod.Status.ContainerStatuses {
		cnt := genContainer(pod, &pod.Status.ContainerStatuses[i], resourceName, resKind, clusterKey, updateTime)
		if poolInfo != nil {
			cnt.PoolName = poolInfo.PoolName
			cnt.PoolUID = poolInfo.PoolUID
			cnt.PoolPodName = poolInfo.PoolPodName
			cnt.PoolPodUID = poolInfo.PoolPodUID
		}
		cnt_rels = append(cnt_rels, cnt)
	}

	oneCtx, cancel := context.WithTimeout(ctx, 5000*time.Millisecond)
	defer cancel()

	if len(cnt_rels) != 0 {
		return rdb.WithContext(oneCtx).Transaction(func(tx *gorm.DB) error {
			tx.WithContext(oneCtx).Model(&model.TensorContainerRelation{}).
				Where("cluster_key = ? AND namespace = ? AND pod_name = ?", clusterKey, pod.Namespace, pod.Name).Updates(map[string]interface{}{"status": terminated})

			return tx.WithContext(oneCtx).Model(&model.TensorContainerRelation{}).Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "id"}},
				DoUpdates: clause.AssignmentColumns([]string{"updated_at", "container_id", "name", "status", "pod_name",
					"time_stamp", "pool_name", "pool_uid", "pool_pod_name", "pool_pod_uid"}),
			}).Create(&cnt_rels).Error
		})
	}
	return nil
}

func DeletePodContainerRelation(ctx context.Context, rdb *gorm.DB, clusterKey, namespace, name string) error {
	rCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 500*time.Millisecond)
		defer oneCancel()

		err := rdb.WithContext(oneCtx).Model(&model.TensorContainerRelation{}).
			Where("cluster_key = ? AND namespace = ? AND pod_name= ?", clusterKey, namespace, name).Updates(map[string]interface{}{
			"status":     terminated,
			"updated_at": time.Now(),
		}).Error

		return err
	})
}

func CleanUpPodContainerRelations(ctx context.Context, rdb *gorm.DB, ts time.Time, clusterKey string) error {
	rCtx, cancel := context.WithTimeout(ctx, 15000*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 5000*time.Millisecond)
		defer oneCancel()
		return rdb.WithContext(oneCtx).Model(&model.TensorContainerRelation{}).
			Where("cluster_key = ?", clusterKey).Updates(map[string]interface{}{
			"status":     terminated,
			"updated_at": time.Now(),
		}).Error
	})
}

func getContainerStatus(status *corev1.ContainerState) int32 {
	if status.Waiting != nil && (status.Waiting.Reason != "" || status.Waiting.Message != "") {
		return waiting
	} else if status.Running != nil && !status.Running.StartedAt.IsZero() {
		return running
	} else if status.Terminated != nil {
		return terminated
	}
	return running
}

type colMultiQuery struct {
	column string
	query  []string
}

type RawContainersQueryOption struct {
	whereEqCondition      map[string]interface{}
	whereNotNullCondition map[string]struct{}
	whereInCondition      map[string]interface{}
	columnQuery           colQuery
	columnQueries         []colMultiQuery
	//mulColQuery           mulColQuery
}

func RawContainersQuery() *RawContainersQueryOption {
	return &RawContainersQueryOption{
		whereEqCondition: make(map[string]interface{}, 3),
		whereInCondition: make(map[string]interface{}, 3),
	}
}

func (q *RawContainersQueryOption) WithCluster(clusterKey string) *RawContainersQueryOption {
	q.whereEqCondition["cluster_key"] = clusterKey
	return q
}

func (q *RawContainersQueryOption) WithNamespace(ns string) *RawContainersQueryOption {
	q.whereEqCondition["namespace"] = ns
	return q
}

func (q *RawContainersQueryOption) WithPodName(ns string) *RawContainersQueryOption {
	q.whereEqCondition["pod_name"] = ns
	return q
}

func (q *RawContainersQueryOption) WithNodeName(ns string) *RawContainersQueryOption {
	q.whereEqCondition["node_name"] = ns
	return q
}

func (q *RawContainersQueryOption) WithContainerName(ns string) *RawContainersQueryOption {
	q.whereEqCondition["name"] = ns
	return q
}

func (q *RawContainersQueryOption) WithID(ns string) *RawContainersQueryOption {
	q.whereEqCondition["id"] = ns
	return q
}

func (q *RawContainersQueryOption) WithK8sManaged(k8s bool) *RawContainersQueryOption {
	q.whereEqCondition["k8s_managed"] = k8s
	return q
}

func (q *RawContainersQueryOption) WithStatus(status int32) *RawContainersQueryOption {
	q.whereEqCondition["status"] = status
	return q
}

func (q *RawContainersQueryOption) WithInConditionCustom(column string, value interface{}) *RawContainersQueryOption {
	q.whereInCondition[column] = value
	return q
}

func (q *RawContainersQueryOption) WithColumnQuery(column, query string) *RawContainersQueryOption {
	q.columnQuery.column = column
	q.columnQuery.query = query
	return q
}

func (q *RawContainersQueryOption) WithColumnMultiQuery(column string, query []string) *RawContainersQueryOption {
	q.columnQueries = append(q.columnQueries, colMultiQuery{
		column: column,
		query:  query,
	})
	return q
}

func CountRawContainer(ctx context.Context, rdb *gorm.DB, queryOptions *RawContainersQueryOption) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 2000*time.Millisecond)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorRawContainer{})

		if len(queryOptions.whereEqCondition) > 0 {
			db = db.Where(queryOptions.whereEqCondition)
		}
		status, statusCondition := queryOptions.whereInCondition["status"]
		if !statusCondition {
			db = db.Where("status < ?", assets.Exited)
		}
		if len(queryOptions.whereInCondition) > 0 {
			if statusCondition && status == assets.All {
				delete(queryOptions.whereInCondition, "status")
			}
			for column, val := range queryOptions.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.columnQuery.column), getLikeExpr(queryOptions.columnQuery.query))
		}
		if len(queryOptions.columnQueries) > 0 {
			for _, c := range queryOptions.columnQueries {
				if len(c.query) > 0 {
					if len(c.query) == 1 {
						db = db.Where(fmt.Sprintf("%s LIKE ?", c.column), getLikeExpr(c.query[0]))
						continue
					}
					subQuery := rdb.WithContext(oneCtx).Model(&model.TensorRawContainer{}).Where(fmt.Sprintf("%s LIKE ?", c.column), getLikeExpr(c.query[0]))
					for _, q := range c.query[1:] {
						subQuery = subQuery.Or(fmt.Sprintf("%s LIKE ?", c.column), getLikeExpr(q))
					}
					db = db.Where(subQuery)
				}
			}
		}
		return db.Count(&cntNum).Error
	})

	return cntNum, err
}

func GetRawContainers(ctx context.Context, rdb *gorm.DB, queryOptions *RawContainersQueryOption, offset int, limit int) ([]*model.TensorRawContainer, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	var containers []*model.TensorRawContainer
	notFound := false
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorRawContainer{})

		if len(queryOptions.whereEqCondition) > 0 {
			db.Where(queryOptions.whereEqCondition)
		}
		status, statusCondition := queryOptions.whereInCondition["status"]
		if !statusCondition {
			db = db.Where("status < ?", assets.Exited)
		}
		if len(queryOptions.whereInCondition) > 0 {
			if statusCondition && status == assets.All {
				delete(queryOptions.whereInCondition, "status")
			}
			for column, val := range queryOptions.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.columnQuery.column), getLikeExpr(queryOptions.columnQuery.query))
		}
		if len(queryOptions.columnQueries) > 0 {
			for _, c := range queryOptions.columnQueries {
				if len(c.query) > 0 {
					if len(c.query) == 1 {
						db = db.Where(fmt.Sprintf("%s LIKE ?", c.column), getLikeExpr(c.query[0]))
						continue
					}
					subQuery := rdb.WithContext(oneCtx).Model(&model.TensorRawContainer{}).Where(fmt.Sprintf("%s LIKE ?", c.column), getLikeExpr(c.query[0]))
					for _, q := range c.query[1:] {
						subQuery = subQuery.Or(fmt.Sprintf("%s LIKE ?", c.column), getLikeExpr(q))
					}
					db = db.Where(subQuery)
				}
			}
		}
		if offset >= 0 && limit >= 0 {
			db.Offset(offset).Limit(limit)
		}

		err := db.Order("id ASC").Find(&containers).Error
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
	return containers, nil
}

func UpsertRawContainers(ctx context.Context, rdb *gorm.DB, container *model.TensorRawContainer) error {
	rCtx, cancel := context.WithTimeout(ctx, 15000*time.Millisecond)
	defer cancel()

	return rdb.WithContext(rCtx).Model(&model.TensorRawContainer{}).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"updated_at",
			"status",
			"name",
			"pod_name",
			"namespace",
			"cluster_key",
			"resource_kind",
			"resource_name",
			"image_id",
			"image_name",
			"environment",
			"volume_mounts",
			"reserved_cpu",
			"reserved_memory",
			"pid",
			"k8s_managed",
			"node_ip",
			"node_name",
			"cmd",
			"image_digest",
			"process_number",
			"processes",
			"ports",
			"image_size",
			"image_created",
			"user",
			"ip",
			"ipv6",
			"gateway",
			"mac",
			"network_mode",
		}),
	}).Create(container).Error
}

func DeleteRawContainer(ctx context.Context, rdb *gorm.DB, clusterKey, id string) error {
	rCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	return rdb.WithContext(rCtx).Model(&model.TensorRawContainer{}).Where("cluster_key = ? and id = ?", clusterKey, id).Updates(map[string]interface{}{
		"status":     assets.Exited,
		"updated_at": time.Now(),
	}).Error
}

func CleanUpRawContainer(ctx context.Context, rdb *gorm.DB, ts time.Time, clusterKey, nodeName string) error {
	rCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	return rdb.WithContext(rCtx).Model(&model.TensorRawContainer{}).
		Where("cluster_key = ? and node_name = ? and updated_at < ?", clusterKey, nodeName, ts).Updates(map[string]interface{}{
		"status":     assets.Exited,
		"updated_at": time.Now(),
	}).Error
}
