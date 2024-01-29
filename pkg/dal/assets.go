package dal

import (
	"context"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/env"
	netv1 "k8s.io/api/networking/v1"
	"strconv"
	"strings"
	"time"

	"github.com/March-deng/godisearch/redisearch"
	json "github.com/json-iterator/go"
	"github.com/spf13/cast"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/request"
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
	Running              = 0
	terminated           = 1
	waiting              = 2

	ContainerState_running = 0
	ContainerState_created = 1
	ContainerState_exited  = 2
	ContainerState_unknown = 3
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
		"generation",
	}
	onDupUpdatedColsForNamespace = []string{
		"owner_references",
		"labels",
		"updated_at",
		"status",
	}
	onDupUpdatedColsForNamespaceLabel = []string{
		"value",
		"updated_at",
		"status",
		"is_block",
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
		"updated_at",
		"status",
		"ready",
	}
	OnDupUpdatedColsForRawContainer = []string{
		"updated_at",
		"status",
		"name",
		"pod_name",
		"pod_uid",
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
		"image_uuid",
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
		"storage_type",
		"last_stop_time",
		"full_name",
		"labels",
	}
	OnDupUpdatedColsForRawCtnFramework = []string{
		"updated_at",
		"status",
		"language_name",
		"language_version",
		"framework_name",
		"framework_version",
		"framework_path",
		"language_bin_path",
	}
	OnDupUpdatedColsForRawCtnSvc = []string{
		"updated_at",
		"status",
		"svc_name",
		"svc_version",
		"svc_type",
		"user",
		"user_group",
		"cmd",
		"port",
		"root_dir",
		"binary_dir",
		"config_dir",
		"data_dir",
		"log_dir",
	}
	OnDupUpdatedColsForIngress = []string{
		"updated_at",
		"status",
		"name",
		"uid",
		"namespace",
		"cluster_key",
	}
	OnDupUpdatedColsForIngressRule = []string{
		"updated_at",
		"status",
		"host",
		"protocol",
		"path",
		"path_type",
		"backend_kind",
		"backend_api_group",
		"backend_name",
		"service_port",
	}
	OnDupUpdatedColsForService = []string{
		"updated_at",
		"status",
		"uid",
		"labels",
		"type",
		"cluster_ip",
		"ports",
		"selector",
	}
	OnDupUpdatedColsForEndpoint = []string{
		"updated_at",
		"uid",
		"status",
	}
	OnDupUpdatedColsForEndpointSubset = []string{
		"updated_at",
		"status",
		"name",
		"namespace",
		"target_ref_kind",
		"address_status",
		"ip",
		"node_name",
		"ports",
	}
	OnDupUpdatedColsForSecret = []string{
		"updated_at",
		"status",
		"uid",
		"labels",
	}
	OnDupUpdatedColsForPV = []string{
		"updated_at",
		"status",
		"access_mode",
		"storage_class_name",
		"volume_mode",
		"storage",
		"pv_status",
		"persistent_volume_reclaim_policy",
		"claim_ref_name",
	}
	OnDupUpdatedColsForPVC = []string{
		"updated_at",
		"status",
		"access_mode",
		"storage_class_name",
		"volume_mode",
		"storage",
		"pv_names",
	}
)

// 禁止修改的标签 业务使用
var BlockNsLabels = []string{"microseg-tenant", "microseg-nsgrp"}

type NamespacesQueryOption struct {
	WhereLikeCondition map[string]string
	whereEqCondition   map[string]interface{}
	whereInCondition   map[string]interface{}
}

func NamespaceQuery() *NamespacesQueryOption {
	return &NamespacesQueryOption{
		WhereLikeCondition: map[string]string{},
		whereEqCondition:   map[string]interface{}{},
		whereInCondition:   map[string]interface{}{},
	}
}

func (n *NamespacesQueryOption) WithFuzzyCluster(clusterKey string) *NamespacesQueryOption {
	n.WhereLikeCondition["cluster_key"] = clusterKey
	return n
}
func (n *NamespacesQueryOption) WithFuzzyName(ns string) *NamespacesQueryOption {
	n.WhereLikeCondition["name"] = ns
	return n
}
func (n *NamespacesQueryOption) WithCluster(clusterKey string) *NamespacesQueryOption {
	n.whereEqCondition["cluster_key"] = clusterKey
	return n
}
func (n *NamespacesQueryOption) WithName(ns string) *NamespacesQueryOption {
	n.whereEqCondition["name"] = ns
	return n
}

func (n *NamespacesQueryOption) WithIdList(idList []string) {
	n.whereInCondition["id"] = idList
}

func CountNamespaces(ctx context.Context, rdb *gorm.DB, clusterKey, nameQuery string) (int64, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var nsCount int64
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.TensorNamespace{}).Where("status = ?", 0)

		if clusterKey != "" {
			db.Where("cluster_key = ?", clusterKey)
		}
		if nameQuery != "" {
			db = db.Where("name LIKE ?", GetLikeExpr(nameQuery))
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
			db = db.Where("name LIKE ?", GetLikeExpr(nameQuery))
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

func CountNamespacesWithOption(ctx context.Context, rdb *gorm.DB, queryOpt *NamespacesQueryOption) (int64, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var nsCount int64
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.TensorNamespace{}).Where("status = ?", 0)

		if len(queryOpt.whereEqCondition) > 0 {
			db = db.Where(queryOpt.whereEqCondition)
		}
		for column, val := range queryOpt.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", column), GetLikeExpr(val))
		}
		for k, v := range queryOpt.whereInCondition {
			rdb = db.Where(fmt.Sprintf("%s in ?", k), v)
		}
		return db.Count(&nsCount).Error
	})
	if err != nil {
		return 0, err
	}
	return nsCount, nil
}

func GetNamespaceWithOption(ctx context.Context, rdb *gorm.DB, queryOpt *NamespacesQueryOption, offset, limit int) ([]*model.TensorNamespace, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var namespaces []*model.TensorNamespace
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		if len(queryOpt.whereEqCondition) > 0 {
			rdb = rdb.Where(queryOpt.whereEqCondition)
		}
		for column, val := range queryOpt.WhereLikeCondition {
			rdb = rdb.Where(fmt.Sprintf("%s LIKE ?", column), GetLikeExpr(val))
		}
		for k, v := range queryOpt.whereInCondition {
			rdb = rdb.Where(fmt.Sprintf("%s in ?", k), v)
		}
		if limit > 0 && offset >= 0 {
			rdb = rdb.Offset(offset).Limit(limit)
		}

		return rdb.WithContext(oneCtx).Model(&model.TensorNamespace{}).
			Where("status = ?", 0).Find(&namespaces).Error
	})
	if err != nil {
		return nil, err
	}
	return namespaces, nil
}

type NamespaceLabelQueryOption struct {
	WhereLikeCondition map[string]string
	WhereEqCondition   map[string]interface{}
	WhereInCondition   map[string]interface{}
	TimeRange          TimeRange
}

func (n *NamespaceLabelQueryOption) WithTimeRange(start, end time.Time) {
	n.TimeRange.start = start
	n.TimeRange.end = end
}

func NamespaceLabelQuery() *NamespaceLabelQueryOption {
	return &NamespaceLabelQueryOption{
		WhereEqCondition:   make(map[string]interface{}),
		WhereLikeCondition: make(map[string]string),
		WhereInCondition:   make(map[string]interface{}),
	}
}

type BusiSvcQueryOption struct {
	WhereLikeCondition map[string]string
	WhereEqCondition   map[string]interface{}
	WhereInCondition   map[string]interface{}
	ContainerName      string
}

func GetBusiSvcQueryOption() *BusiSvcQueryOption {
	return &BusiSvcQueryOption{
		WhereLikeCondition: make(map[string]string, 2),
		WhereEqCondition:   make(map[string]interface{}, 2),
		WhereInCondition:   make(map[string]interface{}, 1),
	}
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
	whereEqCondition   map[string]interface{}
	whereInCondition   map[string]interface{}
	WhereLikeCondition map[string]string
	columnQuery        colQuery
	WithUserAccount    bool
}

func ResourcesQuery() *ResourcesQueryOption {
	return &ResourcesQueryOption{
		whereEqCondition:   make(map[string]interface{}, 3),
		whereInCondition:   make(map[string]interface{}, 2),
		WhereLikeCondition: make(map[string]string),
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
func (q *ResourcesQueryOption) WithFuzzyName(name string) *ResourcesQueryOption {
	q.WhereLikeCondition["name"] = name
	return q
}
func (q *ResourcesQueryOption) WithIdList(idList []string) *ResourcesQueryOption {
	q.whereInCondition["id"] = idList
	return q
}
func (q *ResourcesQueryOption) WithFuzzyNamespace(ns string) *ResourcesQueryOption {
	q.WhereLikeCondition["namespace"] = ns
	return q
}
func (q *ResourcesQueryOption) WithColumnQuery(column, query string) *ResourcesQueryOption {
	q.columnQuery.column = column
	q.columnQuery.query = query
	return q
}

func (q *ResourcesQueryOption) OkForRedis() bool {
	if q.columnQuery.column != "" {
		return false
	}

	if len(q.whereInCondition) != 0 {
		return false
	}

	for k := range q.whereEqCondition {
		if k != "id" && k != "kind" && k != "cluster_key" {
			return false
		}
	}

	for k := range q.WhereLikeCondition {
		if k != "name" && k != "namespace" {
			return false
		}
	}

	return true
}

func (q *ResourcesQueryOption) RedisRawQuery() string {
	rawQuery := &strings.Builder{}

	if !q.OkForRedis() {
		return ""
	}

	v, ok := q.whereEqCondition["kind"]
	if ok {
		rawQuery.WriteString(fmt.Sprintf(` @kind:{%s}`, v))
	}
	v, ok = q.whereEqCondition["cluster_key"]
	if ok {
		rawQuery.WriteString(fmt.Sprintf(` @cluster_key:{%s}`, redisearch.EscapeTextFileString(cast.ToString(v))))
	}
	v, ok = q.whereEqCondition["id"]
	if ok {
		rawQuery.WriteString(fmt.Sprintf(" @id:[%d %d]", cast.ToUint32(v), cast.ToUint32(v)))
	}
	for field, value := range q.WhereLikeCondition {
		rawQuery.WriteString(fmt.Sprintf(" @%s:{*%s*}", field, redisearch.EscapeTextFileString(value)))
	}
	query := rawQuery.String()
	// 如果没有条件，就匹配所有
	if query == "" {
		query = "*"
	}
	return query
}

type ResourceKey struct {
	ClusterKey   string
	Namespace    string
	ResourceKind string
	ResourceName string
}

func GetLikeExpr(s string) string {
	sb := strings.Builder{}
	sb.WriteByte('%')
	sb.WriteString(s)
	sb.WriteByte('%')
	return sb.String()
}

func CountResources(ctx context.Context, rdb *gorm.DB, query *ResourcesQueryOption) (int64, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var resCount int64
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()

		var countErr error

		resCount, countErr = countResourcesFromDB(oneCtx, rdb, query)
		return countErr
	})

	if err != nil {
		return 0, err
	}
	return resCount, nil
}

func countResourcesFromDB(ctx context.Context, rdb *gorm.DB, query *ResourcesQueryOption) (int64, error) {
	var resCount int64
	db := rdb.WithContext(ctx).Model(&model.TensorResource{}).Where("status = ?", 0)
	if len(query.whereEqCondition) > 0 {
		db = db.Where(query.whereEqCondition)
	}
	if len(query.whereInCondition) > 0 {
		for column, val := range query.whereInCondition {
			db = db.Where(fmt.Sprintf("%s in ?", column), val)
		}
	}
	if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
		db = db.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), GetLikeExpr(query.columnQuery.query))
	}
	for col, q := range query.WhereLikeCondition {
		db = db.Where(fmt.Sprintf("%s LIKE ?", col), GetLikeExpr(q))
	}
	err := db.Count(&resCount).Error
	return resCount, err
}

func countResourceFromRedis(ctx context.Context, client *redisearch.Client, query *ResourcesQueryOption) (int64, error) {

	rawQuery := query.RedisRawQuery()

	q := redisearch.NewQuery(rawQuery).SetReturnFields("id").Limit(0, 0)

	_, total, err := client.Search(ctx, q)
	if err != nil {
		return 0, err
	}

	return int64(total), nil
}

func CountResourcesWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, query *ResourcesQueryOption) (int64, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var resCount int64

	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		var countErr error
		if query.OkForRedis() {
			resCount, countErr = countResourceFromRedis(oneCtx, redisClient, query)
		} else {
			resCount, countErr = countResourcesFromDB(oneCtx, rdb, query)
		}
		return countErr
	})

	return resCount, err
}

func GetResources(ctx context.Context, rdb *gorm.DB, query *ResourcesQueryOption, offset, limit int) (resources []*model.TensorResource, err error) {
	pgCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err = util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()
		var queryErr error
		resources, queryErr = getResourcesFromDB(oneCtx, rdb, query, offset, limit)

		return queryErr
	})
	if err != nil {
		return nil, err
	}
	return resources, nil
}

func getResourcesFromDB(ctx context.Context, rdb *gorm.DB, query *ResourcesQueryOption, offset, limit int) (resources []*model.TensorResource, err error) {
	db := rdb.WithContext(ctx).Model(&model.TensorResource{}).Where("status = ?", 0)
	if len(query.whereEqCondition) > 0 {
		db = db.Where(query.whereEqCondition)
	}
	if len(query.whereInCondition) > 0 {
		for column, val := range query.whereInCondition {
			db = db.Where(fmt.Sprintf("%s in ?", column), val)
		}
	}
	if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
		db = db.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), GetLikeExpr(query.columnQuery.query))
	}
	for col, q := range query.WhereLikeCondition {
		db = db.Where(fmt.Sprintf("%s LIKE ?", col), GetLikeExpr(q))
	}
	if limit > 0 && offset >= 0 {
		db = db.Offset(offset).Limit(limit)
	}

	err = db.Order("id ASC").Find(&resources).Error

	return
}

func getResourcesIDFromRedis(ctx context.Context, client *redisearch.Client, query *ResourcesQueryOption, offset, limit int) ([]uint32, int64, error) {
	rawQuery := query.RedisRawQuery()

	fmt.Println(rawQuery)

	q := redisearch.NewQuery(rawQuery).SetReturnFields("id").SetSortBy("id", true).Limit(offset, limit)

	result, total, err := client.Search(ctx, q)
	if err != nil {
		return nil, 0, err
	}
	ids := make([]uint32, 0, len(result))

	for _, doc := range result {
		ids = append(ids, cast.ToUint32(doc.Properties["id"]))
	}
	return ids, cast.ToInt64(total), nil
}

func GetResourcesWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, query *ResourcesQueryOption, offset, limit int) ([]*model.TensorResource, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resources := make([]*model.TensorResource, 0)

	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()

		// declare var here to avoid shadow
		var (
			queryErr error
			ids      []uint32
		)
		if query.OkForRedis() {
			ids, _, queryErr = getResourcesIDFromRedis(oneCtx, redisClient, query, offset, limit)
			if queryErr != nil {
				return queryErr
			}
			if len(ids) == 0 {
				return nil
			}
			resources, queryErr = getResourcesFromDB(oneCtx, rdb, &ResourcesQueryOption{
				whereInCondition: map[string]interface{}{"id": ids},
			}, -1, -1)
		} else {
			resources, queryErr = getResourcesFromDB(oneCtx, rdb, query, offset, limit)
		}

		return queryErr
	})

	return resources, err
}

type ResContainersQueryOption struct {
	WhereEqCondition      map[string]interface{}
	whereNotNullCondition map[string]struct{}
	whereInCondition      map[string]interface{}
	whereGtCondition      map[string]interface{} // 大于条件
	columnQuery           colQuery
}

func ResourceContainersQuery() *ResContainersQueryOption {
	return &ResContainersQueryOption{
		WhereEqCondition:      make(map[string]interface{}, 3),
		whereInCondition:      make(map[string]interface{}, 2),
		whereNotNullCondition: make(map[string]struct{}, 2),
		whereGtCondition:      make(map[string]interface{}, 1),
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
func (q *ResContainersQueryOption) WithLastContainerId(containerId int64) *ResContainersQueryOption {
	q.whereGtCondition["id"] = containerId
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
	pgCtx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cntNum int64

	db := rdb.WithContext(pgCtx).Model(&model.TensorRawContainer{})
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
	if len(query.whereGtCondition) > 0 {
		for k, v := range query.whereGtCondition {
			db = db.Where(fmt.Sprintf("%s > ?", k), v)
		}
	}
	if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
		db = db.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), GetLikeExpr(query.columnQuery.query))
	}
	db = db.Where("status = ?", 0)
	err := db.Count(&cntNum).Error
	if err != nil {
		return 0, err
	}
	return cntNum, nil
}

type ResContainerBase struct {
	ID               int64  `gorm:"column:id;type:bigint;primaryKey" json:"id,omitempty"`
	Name             string `gorm:"column:name"`
	ResourceName     string `gorm:"column:resource_name;index:idx_tc_list_q,priority:4"`
	Namespace        string `gorm:"column:namespace;index:idx_tc_list_q,priority:2"`
	ClusterKey       string `gorm:"column:cluster_key;index:idx_tc_list_q,priority:1"`
	ResourceKind     string `gorm:"column:resource_kind;index:idx_tc_list_q,priority:3"`
	Image            string `gorm:"column:image"`
	Type             string `gorm:"column:type"`
	ImageUUID        uint32 `gorm:"column:image_uuid"`
	AppType          *string
	AppTargetName    *string
	AppTargetVersion *string
}

func GetResourceContainerBases(ctx context.Context, rdb *gorm.DB, query *ResContainersQueryOption, offset, limit int) (containers []*ResContainerBase, err error) {
	pgCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 9000*time.Millisecond)
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
		if len(query.whereGtCondition) > 0 {
			for k, v := range query.whereGtCondition {
				db = db.Where(fmt.Sprintf("%s > ?", k), v)
			}
		}
		if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), GetLikeExpr(query.columnQuery.query))
		}
		if limit > 0 && offset >= 0 {
			db = db.Offset(offset).Limit(limit)
		}
		// return db.Order("id ASC").Find(&containers).Error
		return db.Order("id ASC").Scan(&containers).Error
	})
	if err != nil {
		return nil, err
	}
	return containers, nil
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
		if len(query.whereGtCondition) > 0 {
			for k, v := range query.whereGtCondition {
				db = db.Where(fmt.Sprintf("%s > ?", k), v)
			}
		}
		if len(query.columnQuery.column) > 0 && len(query.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), GetLikeExpr(query.columnQuery.query))
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

func SoftDeleteResourceWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, resource *assets.TensorResource, updateTime time.Time) error {

	uuid := GetResourceUUID(resource.Cluster, resource.Namespace, string(resource.Kind), resource.Name)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	return rdb.WithContext(ctx).Transaction(func(db *gorm.DB) error {
		err := doSoftDeleteResource(ctx, db, uuid, updateTime)
		if err != nil {
			return err
		}

		doc, err := redisClient.GetDoc(ctx, fmt.Sprintf("resource:%d", uuid))
		if err != nil && err != redisearch.ErrDocNotFound {
			return err
		}

		if doc != nil {
			err = redisClient.DeleteDoc(ctx, fmt.Sprintf("resource:%d", uuid))
			if err != nil {
				return err
			}
			images := make([]uint32, 0)

			for _, image := range strings.Split(cast.ToString(doc.Properties["images"]), ",") {
				images = append(images, cast.ToUint32(image))
			}

			logging.GetLogger().Info().Msgf("delete resource %d container images: %v", uuid, images)
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
	m.Generation = resource.Generation
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

func upsertRedisDocument(ctx context.Context, client *redisearch.Client, doc redisearch.Document) error {
	err := client.DeleteDoc(ctx, doc.Id)
	if err != nil {
		return err
	}

	return client.AddDoc(ctx, doc)
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

func UpsertResourceWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, resource *assets.TensorResource, updateTime time.Time) (*model.TensorResource, error) {
	resourceModel := newModelFromTensorResource(resource, updateTime)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err := rdb.WithContext(ctx).Transaction(func(db *gorm.DB) error {
		containers, err := doUpsertResourceContainers(ctx, db, resource, updateTime)
		if err != nil {
			return err
		}
		err = doUpsertResource(ctx, db, resourceModel, updateTime)
		if err != nil {
			return err
		}

		images := make([]uint32, 0)

		for _, container := range containers {
			images = append(images, container.ImageUUID)
		}

		return doUpsertResourceRedis(ctx, redisClient, resourceModel, images, updateTime)
	})

	return resourceModel, err
}

func doUpsertResourceRedis(ctx context.Context, client *redisearch.Client, resource *model.TensorResource, images []uint32, updateTime time.Time) error {

	var imageS []string

	for _, image := range images {
		imageS = append(imageS, cast.ToString(image))
	}

	docID := fmt.Sprintf("resource:%d", resource.ID)

	doc := redisearch.NewDocument(docID, 1).
		Set("id", resource.ID).
		Set("name", resource.Name).
		Set("namespace", resource.Namespace).
		Set("cluster_key", resource.ClusterKey).
		Set("kind", resource.Kind).
		Set("updated_at", updateTime.UnixMilli()).
		Set("generation", resource.Generation).
		Set("images", strings.Join(imageS, ","))

	return upsertRedisDocument(ctx, client, doc)
}

// container_images  rawContainerUUID ： imageUUID
func addResourceImageByRawContainer(ctx context.Context, redisClient *redisearch.Client, rawContainerUUID uint32, imageUUID uint32) error {
	if rawContainerUUID == 0 || imageUUID == 0 {
		return nil
	}
	conn, err := redisClient.GetConn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	args := make([]interface{}, 0)
	args = append(args, "container_images")
	args = append(args, imageUUID, fmt.Sprintf("%d", rawContainerUUID))

	_, err = conn.Do("ZADD", args...)

	return err
}
func deleteResourceImageByRawContainer(ctx context.Context, redisClient *redisearch.Client, rawContainerUUIDList []uint32) error {
	if len(rawContainerUUIDList) == 0 {
		return nil
	}
	conn, err := redisClient.GetConn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	args := make([]interface{}, 0)
	args = append(args, "container_images")

	for _, uuid := range rawContainerUUIDList {
		if uuid == 0 {
			continue
		}
		args = append(args, fmt.Sprintf("%d", uuid))
	}

	_, err = conn.Do("ZREM", args...)
	return err
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
	//contModel.ImageUUID = util.GenerateUUID(container.Image)
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

		// TODO: may be removed later
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
func UpsertContainerImageUuid(ctx context.Context, rdb *gorm.DB, containerId uint32, imageUuid uint32) error {
	return rdb.WithContext(ctx).Model(&model.TensorContainer{}).Where("id = ?", containerId).Update("image_uuid", imageUuid).Error
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

func CleanUpUnUpdatedResourcesWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, ts time.Time, clusterKey string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()

		err := rdb.WithContext(oneCtx).Model(&model.TensorResource{}).Where("updated_at < ? AND status = ? AND cluster_key = ?", ts, 0, clusterKey).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": ts,
		}).Error
		if err != nil {
			return err
		}

		return cleanUpResourcesFromRedis(oneCtx, redisClient, ts, clusterKey)
	})
}

func cleanUpResourcesFromRedis(ctx context.Context, redisClient *redisearch.Client, ts time.Time, clusterKey string) error {
	updatedAt := ts.UnixMilli()
	rawQuery := fmt.Sprintf("@cluster_key:{%s} @updated_at:[-inf (%d]", redisearch.EscapeTextFileString(clusterKey), updatedAt)

	query := redisearch.NewQuery(rawQuery).SetReturnFields("id", "images")

	result, _, err := redisClient.Search(ctx, query)
	if err != nil {
		return err
	}

	if len(result) == 0 {
		return nil
	}

	keys := make([]string, 0, len(result))
	imageKeys := make([]interface{}, 0)
	imageKeys = append(imageKeys, "container_images")

	for _, doc := range result {
		keys = append(keys, doc.Id)
		for _, image := range strings.Split(cast.ToString(doc.Properties["images"]), ",") {
			imageKeys = append(imageKeys, fmt.Sprintf("%s/%s", doc.Properties["id"], image))
		}
	}

	err = redisClient.DeleteDoc(ctx, keys...)
	if err != nil {
		return err
	}

	conn, err := redisClient.GetConn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Do("ZREM", imageKeys...)
	return err
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
	}

	nsModel.CreatedAt = ns.CreationTimestamp.Time
	nsModel.UpdatedAt = updateTime
	nsModel.Status = 0

	return nsModel
}

func UpsertNamespace(ctx context.Context, rdb *gorm.DB, ns *corev1.Namespace, clusterKey string, updateTime time.Time) (*model.TensorNamespace, error) {
	nsModel := fromNamespaceToModel(ns, clusterKey, updateTime)

	var labels []*model.TensorNamespaceLabel
	for key, value := range ns.Labels {
		labels = append(labels, &model.TensorNamespaceLabel{
			TableBase: model.TableBase{
				ID:        util.GenerateUUID(clusterKey, ns.Name, key),
				CreatedAt: updateTime,
				UpdatedAt: updateTime,
			},
			Name:       key,
			Namespace:  ns.Name,
			ClusterKey: clusterKey,
			Value:      value,
			IsBlock:    IsBlockLabel(key),
		})
	}
	oneCtx, oneCancel := context.WithTimeout(ctx, 2000*time.Millisecond)
	defer oneCancel()

	err := rdb.WithContext(oneCtx).Transaction(func(tx *gorm.DB) error {
		err := tx.Model(nsModel).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForNamespace),
		}).Create(nsModel).Error
		if err != nil {
			return err
		}
		if len(labels) > 0 {
			err = tx.Model(&model.TensorNamespaceLabel{}).Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "id"}},
				DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForNamespaceLabel),
			}).Create(&labels).Error
			if err != nil {
				return err
			}
		}
		deleteTime := updateTime.Add(-1 * time.Second * time.Duration(1)) // 避免将本次的记录删掉
		err = tx.Where("cluster_key=? and namespace=? and updated_at < ?", clusterKey, ns.Name, deleteTime).Delete(&model.TensorNamespaceLabel{}).Error
		return err
	})

	return nsModel, err
}

func IsBlockLabel(labelKey string) bool {
	for _, label := range BlockNsLabels {
		if label == labelKey {
			return true
		}
	}
	return false
}

func SoftDeleteNamespace(ctx context.Context, rdb *gorm.DB, ns *corev1.Namespace, clusterKey string, updateTime time.Time) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer oneCancel()

	id := util.GenerateUUID(clusterKey, ns.Name)

	return rdb.WithContext(oneCtx).Transaction(func(tx *gorm.DB) error {
		err := tx.Model(&model.TensorNamespace{}).Where("id = ? AND status = ?", id, 0).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": updateTime,
		}).Error
		if err != nil {
			return err
		}
		return tx.Where("cluster_key=? and namespace=?", clusterKey, ns.Name).Delete(model.TensorNamespaceLabel{}).Error
	})
}

func CleanUpUnUpdatedNamespaces(ctx context.Context, rdb *gorm.DB, ts time.Time, clusterKey string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
		defer cancel()

		now := time.Now()
		return rdb.WithContext(oneCtx).Transaction(func(tx *gorm.DB) error {
			err := tx.Model(&model.TensorNamespace{}).Where("updated_at < ? AND status = ? AND cluster_key = ?", ts, 0, clusterKey).Updates(map[string]interface{}{
				"status":     1,
				"updated_at": now,
			}).Error
			if err != nil {
				return err
			}
			return tx.Where("cluster_key=?  and updated_at < ?", clusterKey, now).Delete(&model.TensorNamespaceLabel{}).Error
		})
	})
}

// func getRedisKeyForPodResRelByName(clusterKey, namespace, podName string) string {
// 	return fmt.Sprintf("podname-res-rel:%s/%s/%s", clusterKey, namespace, podName)
// }
// func getRedisKeyForPodResRelByPodIP(clusterKey, podIP string) string {
// 	return fmt.Sprintf("podip-res-rel:%s/%s", clusterKey, podIP)
// }
// func getRedisKeyForPodResRelByUID(clusterKey, podUID string) string {
// 	return fmt.Sprintf("poduid-res-rel:%s/%s", clusterKey, podUID)
// }
// func getRedisKeyForResourceControlled(clusterKey, namespace, kind, name string) string {
// 	return fmt.Sprintf("res-controlled:%s/%s/%s/%s", clusterKey, namespace, kind, name)
// }

// type prqKind string

// const (
// 	podIP   prqKind = "podIP"
// 	podUID  prqKind = "podUID"
// 	podName prqKind = "podName"
// )

func GetPodInfoFromK8sClient(ctx context.Context, k8sCli *kubernetes.Clientset, namespace, podName string) (*corev1.Pod, error) {
	return k8sCli.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
}

func newPodResourceRelationFromPod(pod *corev1.Pod, resourceName, resKind, clusterKey string, updateTime time.Time) *model.PodResourceRelation {
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

	rel := &model.PodResourceRelation{
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

	return rel
}

func UpsertPodResourceRelationInRDB(ctx context.Context, rdb *gorm.DB, pod *corev1.Pod, resourceName, resKind, clusterKey string, updateTime time.Time) error {
	rel := newPodResourceRelationFromPod(pod, resourceName, resKind, clusterKey, updateTime)
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

func UpsertPodResourceRelationWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, pod *corev1.Pod, resourceName, resKind, clusterKey string, updateTime time.Time) error {
	rel := newPodResourceRelationFromPod(pod, resourceName, resKind, clusterKey, updateTime)
	rCtx, cancel := context.WithTimeout(ctx, 5000*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(rCtx, func() error {

		oneCtx, oneCancel := context.WithTimeout(rCtx, 1000*time.Millisecond)
		defer oneCancel()
		return rdb.WithContext(oneCtx).Transaction(func(tx *gorm.DB) error {
			err := tx.Model(&rel).Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "id"}},
				DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForPodResRel),
			}).Create(&rel).Error

			if err != nil {
				return err
			}

			docID := fmt.Sprintf("pod:%d", rel.ID)

			doc := redisearch.NewDocument(docID, 1).
				Set("id", rel.ID).
				Set("pod_name", rel.PodName).
				Set("cluster_key", rel.ClusterKey).
				Set("node_name", rel.NodeName).
				Set("resource_kind", rel.ResourceKind).
				Set("resource_name", rel.ResourceName).
				Set("namespace", rel.Namespace).
				Set("pod_ip", rel.PodIP).
				Set("updated_at", rel.UpdatedAt.UnixMilli()).
				Set("created_at", rel.CreatedAt.UnixMilli())
			return upsertRedisDocument(oneCtx, redisClient, doc)
		})
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

func DeletePodResourceRelationWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, clusterKey, namespace, name string) error {
	rCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	return util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 500*time.Millisecond)
		defer oneCancel()

		return rdb.WithContext(oneCtx).Transaction(func(tx *gorm.DB) error {
			err := tx.Where("cluster_key = ? AND namespace = ? AND pod_name= ?", clusterKey, namespace, name).Delete(&model.PodResourceRelation{}).Error

			if err != nil && err != gorm.ErrRecordNotFound {
				return err
			}
			// search for doc
			query := fmt.Sprintf("@cluster_key:{%s} @namespace:{%s} @pod_name:{%s}", redisearch.EscapeTextFileString(clusterKey), redisearch.EscapeTextFileString(namespace), redisearch.EscapeTextFileString(name))
			_, total, err := redisClient.Search(oneCtx, redisearch.NewQuery(query).Limit(0, 0))
			if err != nil {
				return err
			}

			result, _, err := redisClient.Search(oneCtx, redisearch.NewQuery(query).Limit(0, total).SetReturnFields("id"))
			if err != nil {
				return err
			}

			keys := make([]string, 0, len(result))

			for _, doc := range result {
				keys = append(keys, doc.Id)
			}

			if len(keys) != 0 {
				return redisClient.DeleteDoc(oneCtx, keys...)
			}

			return nil
		})
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

func CleanUpPodResourceRelationWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, ts time.Time, clusterKey string) error {
	rCtx, cancel := context.WithTimeout(ctx, 15000*time.Millisecond)
	defer cancel()
	rawQuery := fmt.Sprintf("@updated_at:[-inf (%d] @cluster_key:{%s}", ts.UnixMilli(), redisearch.EscapeTextFileString(clusterKey))

	return util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 5000*time.Millisecond)
		defer oneCancel()
		_, total, err := redisClient.Search(oneCtx, redisearch.NewQuery(rawQuery).Limit(0, 0))
		if err != nil {
			return err
		}

		result, _, err := redisClient.Search(oneCtx, redisearch.NewQuery(rawQuery).Limit(0, total).SetReturnFields("id"))
		if err != nil {
			return err
		}
		keys := make([]string, 0, len(result))

		for _, doc := range result {
			keys = append(keys, doc.Id)
		}

		return rdb.WithContext(oneCtx).Transaction(func(tx *gorm.DB) error {
			err := rdb.Where("updated_at < ? AND cluster_key = ?", ts, clusterKey).Delete(&model.PodResourceRelation{}).Error
			if err != nil {
				return err
			}
			if len(keys) != 0 {
				return redisClient.DeleteDoc(oneCtx, keys...)
			}
			return nil

		})
	})
}

type TimeRange struct {
	start time.Time
	end   time.Time
}
type ResPodsQueryOption struct {
	whereEqCondition   map[string]interface{}
	whereInCondition   map[string]interface{}
	WhereLikeCondition map[string]string
	columnQuery        colQuery
	mulColQuery        mulColQuery
	timeRange          TimeRange
}

func ResourcePodssQuery() *ResPodsQueryOption {
	return &ResPodsQueryOption{
		whereEqCondition:   make(map[string]interface{}, 3),
		whereInCondition:   make(map[string]interface{}, 2),
		WhereLikeCondition: make(map[string]string, 3),
	}
}

func (q *ResPodsQueryOption) GetClusterOption() (string, bool) {
	v, ok := q.whereEqCondition["cluster_key"]
	if !ok {
		return "", false
	}
	return v.(string), ok
}
func (q *ResPodsQueryOption) WithFuzzyCluster(clusterKey string) *ResPodsQueryOption {
	q.WhereLikeCondition["cluster_key"] = clusterKey
	return q
}
func (q *ResPodsQueryOption) WithFuzzyNodeName(nodeName string) *ResPodsQueryOption {
	q.WhereLikeCondition["node_name"] = nodeName
	return q
}
func (q *ResPodsQueryOption) WithFuzzyNamespace(ns string) *ResPodsQueryOption {
	q.WhereLikeCondition["namespace"] = ns
	return q
}
func (q *ResPodsQueryOption) WithFuzzyResourceKind(kind assets.ResourceKind) *ResPodsQueryOption {
	q.WhereLikeCondition["resource_kind"] = string(kind)
	return q
}
func (q *ResPodsQueryOption) WithFuzzyResourceName(name string) *ResPodsQueryOption {
	q.WhereLikeCondition["resource_name"] = name
	return q
}
func (q *ResPodsQueryOption) WithFuzzyName(cname string) *ResPodsQueryOption {
	q.WhereLikeCondition["pod_name"] = cname
	return q
}
func (q *ResPodsQueryOption) WithFuzzyPodIP(ip string) *ResPodsQueryOption {
	q.WhereLikeCondition["pod_ip"] = ip
	return q
}
func (q *ResPodsQueryOption) WithIdList(idList []string) *ResPodsQueryOption {
	q.whereInCondition["id"] = idList
	return q
}
func (q *ResPodsQueryOption) WithCluster(clusterKey string) *ResPodsQueryOption {
	q.whereEqCondition["cluster_key"] = clusterKey
	return q
}
func (q *ResPodsQueryOption) WithNamespace(ns string) *ResPodsQueryOption {
	q.whereEqCondition["namespace"] = ns
	return q
}
func (q *ResPodsQueryOption) WithName(cname string) *ResPodsQueryOption {
	q.whereEqCondition["pod_name"] = cname
	return q
}
func (q *ResPodsQueryOption) WithResourceKind(kind assets.ResourceKind) *ResPodsQueryOption {
	q.whereEqCondition["resource_kind"] = string(kind)
	return q
}
func (q *ResPodsQueryOption) WithResourceName(name string) *ResPodsQueryOption {
	q.whereEqCondition["resource_name"] = name
	return q
}
func (q *ResPodsQueryOption) WithNodeName(nodeName string) *ResPodsQueryOption {
	q.whereEqCondition["node_name"] = nodeName
	return q
}
func (q *ResPodsQueryOption) WithPodIP(ip string) *ResPodsQueryOption {
	q.whereEqCondition["pod_ip"] = ip
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

func (q *ResPodsQueryOption) WithInPodNameList(podNames []string) *ResPodsQueryOption {
	q.whereInCondition["pod_name"] = podNames
	return q
}

func (q *ResPodsQueryOption) WithTimeRange(start, end time.Time) *ResPodsQueryOption {
	q.timeRange.start = start
	q.timeRange.end = end
	return q
}

// 精确匹配: cluster_key, resource_kind,
// 模糊匹配: pod_name, pod_ip, node_name, resource_name, namespace
// 范围匹配：created_at
func (q *ResPodsQueryOption) OkForRedis() bool {
	if len(q.whereInCondition) != 0 {
		return false
	}

	allowFields := map[string]struct{}{
		"pod_name":      {},
		"node_name":     {},
		"resource_name": {},
		"namespace":     {},
		"pod_ip":        {},
	}

	likeFields := make([]string, 0)
	if q.columnQuery.column != "" {
		likeFields = append(likeFields, q.columnQuery.column)
	}

	likeFields = append(likeFields, q.mulColQuery.columns...)

	for f := range q.WhereLikeCondition {
		likeFields = append(likeFields, f)
	}
	// 没有like查询不需要使用redis
	if len(likeFields) == 0 {
		return false
	}

	for _, f := range likeFields {
		_, ok := allowFields[f]
		if !ok {
			return false
		}
	}

	for f := range q.whereEqCondition {
		if f != "cluster_key" && f != "resource_kind" && f != "namespace" {
			return false
		}
	}

	return true
}

func (q *ResPodsQueryOption) RedisRawQuery() string {
	if !q.OkForRedis() {
		return ""
	}

	builder := &strings.Builder{}

	if v, ok := q.whereEqCondition["cluster_key"]; ok {
		builder.WriteString(fmt.Sprintf("@cluster_key:{%s}", redisearch.EscapeTextFileString(cast.ToString(v))))
	}

	if v, ok := q.whereEqCondition["kind"]; ok {
		builder.WriteString(fmt.Sprintf("@kind:{%s}", v))
	}

	if v, ok := q.whereEqCondition["namespace"]; ok {
		builder.WriteString(fmt.Sprintf("@namespace:{%s} ", redisearch.EscapeTextFileString(cast.ToString(v))))
	}

	if !q.timeRange.start.IsZero() || !q.timeRange.end.IsZero() {
		start := "-inf"
		end := "+inf"

		if !q.timeRange.start.IsZero() {
			start = fmt.Sprintf("(%d", q.timeRange.start.UnixMilli())
		}

		if !q.timeRange.end.IsZero() {
			end = fmt.Sprintf("(%d", q.timeRange.end.UnixMilli())
		}

		builder.WriteString(fmt.Sprintf("@created_at:[%s %s]", start, end))
	}

	likeFields := make(map[string]string)

	for f, v := range q.WhereLikeCondition {
		likeFields[f] = v
	}

	if q.columnQuery.column != "" && q.columnQuery.query != "" {
		likeFields[q.columnQuery.column] = q.columnQuery.query
	}

	for f, v := range likeFields {
		builder.WriteString(fmt.Sprintf("@%s:{*%s*}", f, redisearch.EscapeTextFileString(v)))
	}

	return builder.String()
}

func GetResourcePodListWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, queryOptions *ResPodsQueryOption, offset, limit int) ([]*model.PodResourceRelation, error) {
	if !queryOptions.OkForRedis() {
		return GetResourcePodsList(ctx, rdb, queryOptions, offset, limit)
	}

	rctx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
	defer cancel()

	rawQuery := queryOptions.RedisRawQuery()

	query := redisearch.NewQuery(rawQuery).Limit(offset, limit).SetReturnFields("id").SetSortBy("id", true)

	var (
		rels     []*model.PodResourceRelation
		queryErr error
	)

	err := util.RetryWithBackoff(rctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rctx, 500*time.Millisecond)
		defer oneCancel()

		result, _, err := redisClient.Search(oneCtx, query)

		if err != nil {
			return err
		}

		ids := make([]uint32, 0, len(result))

		for _, doc := range result {
			ids = append(ids, cast.ToUint32(doc.Properties["id"]))
		}

		if len(ids) == 0 {
			return nil
		}

		rels, queryErr = getResourcePodByIds(oneCtx, rdb, ids)

		return queryErr
	})

	return rels, err
}

func getResourcePodByIds(ctx context.Context, rdb *gorm.DB, ids []uint32) ([]*model.PodResourceRelation, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var rels []*model.PodResourceRelation

	db := rdb.WithContext(ctx).Model(&model.PodResourceRelation{}).Where("status = ?", 0)

	if len(ids) != 0 {
		db = db.Where("id in ?", ids).Order("id ASC")
	}

	err := db.Find(&rels).Error

	return rels, err
}

// FIXME: 这个函数没有order by
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

		if len(queryOptions.WhereLikeCondition) > 0 {
			for column, val := range queryOptions.WhereLikeCondition {
				db = db.Where(fmt.Sprintf("%s LIKE ?", column), GetLikeExpr(val))
			}
		}

		if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.columnQuery.column), GetLikeExpr(queryOptions.columnQuery.query))
		}

		if len(queryOptions.mulColQuery.columns) > 0 && len(queryOptions.mulColQuery.query) > 0 {
			expr := GetLikeExpr(queryOptions.mulColQuery.query)
			db = db.Where(
				rdb.WithContext(oneCtx).Model(&model.PodResourceRelation{}).Where("pod_name LIKE ?", expr).
					Or("pod_ip LIKE ?", expr).Or("node_name LIKE ?", expr))
		}

		if queryOptions.timeRange.start.IsZero() && !queryOptions.timeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.timeRange.end)
		} else if !queryOptions.timeRange.start.IsZero() && queryOptions.timeRange.end.IsZero() {
			db = db.Where("created_at > ?", queryOptions.timeRange.start)
		} else if !queryOptions.timeRange.start.IsZero() && !queryOptions.timeRange.end.IsZero() {
			db = db.Where("created_at > ? and created_at < ?", queryOptions.timeRange.start, queryOptions.timeRange.end)
		}

		db = db.Order("id ASC")

		if offset >= 0 && limit >= 0 {
			db = db.Offset(offset).Limit(limit)
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

func GetPodNameListBySvc(ctx context.Context, rdb *gorm.DB, clusterKey string, namespace string, svcName string) ([]string, error) {
	rctx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
	defer cancel()

	var podNameList []string

	err := rdb.WithContext(rctx).Model(&model.TensorEndpointsSubset{}).Joins("join ivan_assets_endpoints end on end.id=ivan_assets_endpointsSubsets.endpoints_id").
		Where("end.cluster_key=? and end.namespace=? and end.name = ? and end.status=0", clusterKey, namespace, svcName).Distinct("ivan_assets_endpointsSubsets.name").Scan(&podNameList).Error
	if err != nil {
		return nil, err
	}
	return podNameList, nil
}

func CountPodsWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, queryOptions *ResPodsQueryOption) (int64, error) {

	if !queryOptions.OkForRedis() {
		return CountPods(ctx, rdb, queryOptions)
	}

	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cnt int64

	query := redisearch.NewQuery(queryOptions.RedisRawQuery()).Limit(0, 0)

	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 4*time.Second)
		defer oneCancel()

		_, total, err := redisClient.Search(oneCtx, query)

		if err != nil {
			return err
		}

		cnt = int64(total)

		return nil
	})
	return cnt, err
}

func CountPods(ctx context.Context, rdb *gorm.DB, queryOptions *ResPodsQueryOption) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 4*time.Second)
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
			db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.columnQuery.column), GetLikeExpr(queryOptions.columnQuery.query))
		}

		if len(queryOptions.WhereLikeCondition) > 0 {
			for column, val := range queryOptions.WhereLikeCondition {
				db = db.Where(fmt.Sprintf("%s LIKE ?", column), GetLikeExpr(val))
			}
		}

		if len(queryOptions.mulColQuery.columns) > 0 && len(queryOptions.mulColQuery.query) > 0 {
			expr := GetLikeExpr(queryOptions.mulColQuery.query)
			db = db.Where(
				rdb.WithContext(oneCtx).Model(&model.PodResourceRelation{}).Where("pod_name LIKE ?", expr).Or("pod_ip LIKE ?", expr).Or("node_name LIKE ?", expr))
		}

		if queryOptions.timeRange.start.IsZero() && !queryOptions.timeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.timeRange.end)
		} else if !queryOptions.timeRange.start.IsZero() && queryOptions.timeRange.end.IsZero() {
			db = db.Where("created_at > ?", queryOptions.timeRange.start)
		} else if !queryOptions.timeRange.start.IsZero() && !queryOptions.timeRange.end.IsZero() {
			db = db.Where("created_at > ? and created_at < ?", queryOptions.timeRange.start, queryOptions.timeRange.end)
		}

		return db.Count(&cntNum).Error
	})

	return cntNum, err
}

func ClusterQuery() *ClusterQueryOption {
	return &ClusterQueryOption{
		WhereEqCondition:   make(map[string]interface{}),
		WhereLikeCondition: make(map[string]string),
		WhereInCondition:   make(map[string]interface{}),
		columnQuery:        colQuery{},
		mulColQuery:        mulColQuery{},
	}

}

type ClusterQueryOption struct {
	WhereEqCondition   map[string]interface{}
	WhereInCondition   map[string]interface{}
	WhereLikeCondition map[string]string
	columnQuery        colQuery
	mulColQuery        mulColQuery
}

func (q *ClusterQueryOption) WithKey(clusterKey string) *ClusterQueryOption {
	q.WhereLikeCondition["id"] = clusterKey
	return q
}

func (q *ClusterQueryOption) WithName(name string) *ClusterQueryOption {
	q.WhereLikeCondition["name"] = name
	return q
}

func (q *ClusterQueryOption) WithAPIServerAddr(addr string) *ClusterQueryOption {
	q.WhereLikeCondition["api_server_addr"] = addr
	return q
}

func (q *ClusterQueryOption) WithVersion(version string) *ClusterQueryOption {
	q.WhereLikeCondition["version"] = version
	return q
}

func (q *ClusterQueryOption) WithType(t string) *ClusterQueryOption {
	q.WhereEqCondition["cluster_type"] = t
	return q
}

func (q *ClusterQueryOption) WithPlatform(platform string) *ClusterQueryOption {
	q.WhereEqCondition["platform"] = platform
	return q
}
func (q *ClusterQueryOption) WithIdList(idList []string) *ClusterQueryOption {
	q.WhereInCondition["id"] = idList
	return q
}
func (q *ClusterQueryOption) WithRulesVersion(version string) *ClusterQueryOption {
	q.WhereEqCondition["rule_version"] = version
	return q
}

func GetClusters(ctx context.Context, rdb *gorm.DB, query *ClusterQueryOption, offset, limit int) (clusters []*model.TensorCluster, err error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	err = util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		if len(query.WhereEqCondition) > 0 {
			rdb = rdb.Where(query.WhereEqCondition)
		}
		if len(query.WhereLikeCondition) > 0 {
			for column, val := range query.WhereLikeCondition {
				rdb = rdb.Where(fmt.Sprintf("%s LIKE ?", column), GetLikeExpr(val))
			}
		}
		for k, v := range query.WhereInCondition {
			rdb = rdb.Where(fmt.Sprintf("%s in ?", k), v)
		}

		oneErr := rdb.WithContext(oneCtx).Model(&model.TensorCluster{}).Where("status = ?", 0).Order("id").Offset(offset).Limit(limit).Find(&clusters).Error
		if oneErr != nil {
			return oneErr
		}
		return nil
	})
	return
}

func GetClusterKeyList(ctx context.Context, rdb *gorm.DB) (keys []string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()
	err = util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		oneErr := rdb.WithContext(oneCtx).Model(&model.TensorCluster{}).Where("status = ?", 0).Select("id").Order("id").Scan(&keys).Error
		if oneErr != nil {
			return oneErr
		}
		return nil
	})
	return
}

func GetPodNamespace(ctx context.Context, rdb *gorm.DB, keys []string) (nsMap map[string]string, err error) {
	nsMap = make(map[string]string)
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()
	for _, key := range keys {
		var rawContainer model.TensorRawContainer
		oneErr := rdb.WithContext(ctx).Model(&model.TensorRawContainer{}).Where("cluster_key = ? and name ='cluster-manager' and  status = ?", key, 0).Select("environment").Take(&rawContainer).Error
		if oneErr != nil {
			logging.GetLogger().Err(oneErr).Msgf("find env:soft_name failed, clusterKey:%s", key)
			continue
		}
		for _, str := range rawContainer.Environment {
			if strings.Contains(str, env.MyNamespace) {
				nsMap[key] = str[len(env.MyNamespace)+1:]
				break
			}
		}
	}
	return
}

func CountClusters(ctx context.Context, rdb *gorm.DB, query *ClusterQueryOption) (totalCnt int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	err = util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		if len(query.WhereEqCondition) > 0 {
			rdb = rdb.Where(query.WhereEqCondition)
		}
		if len(query.WhereLikeCondition) > 0 {
			for column, val := range query.WhereLikeCondition {
				rdb = rdb.Where(fmt.Sprintf("%s LIKE ?", column), GetLikeExpr(val))
			}
		}
		for k, v := range query.WhereInCondition {
			rdb = rdb.Where(fmt.Sprintf("%s in ?", k), v)
		}
		return rdb.WithContext(oneCtx).Model(&model.TensorCluster{}).Where("status = ?", 0).Count(&totalCnt).Error
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
func GetClustersByKeys(ctx context.Context, rdb *gorm.DB, keys []string) []model.TensorCluster {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()
	var clusters []model.TensorCluster
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		return rdb.WithContext(oneCtx).Model(&model.TensorCluster{}).Where("status = ? AND id in ?", 0, keys).Find(&clusters).Error
	})
	if err != nil {
		return nil
	}

	return clusters
}
func UpdateCluster(ctx context.Context, rdb *gorm.DB, clusterKey string, clusterName, description, ruleVersion string) error {
	if clusterKey == "" {
		return errors.New("illegal cluster key argument")
	}
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	userInfo, ok := request.GetSessionFromContext(ctx)
	updateMap := map[string]interface{}{
		"updated_at": time.Now(),
	}
	if ok {
		updateMap["updater"] = userInfo.Username
	}
	if clusterName != "" {
		updateMap["name"] = clusterName
	}
	if description != "" {
		updateMap["description"] = description
	}
	if ruleVersion != "" {
		updateMap["rule_version"] = ruleVersion
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

	userInfo, ok := request.GetSessionFromContext(ctx)
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
		return rdb.WithContext(oneCtx).Model(&model.TensorCluster{}).
			Where("id = ?", clusterKey).Update("status", 1).Error
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
	whereEqCondition   map[string]interface{}
	whereInCondition   map[string]interface{}
	WhereLikeCondition map[string]string
	columnQuery        colQuery
}

func NodeQuery() *NodeQueryOption {
	return &NodeQueryOption{
		whereEqCondition:   make(map[string]interface{}, 3),
		whereInCondition:   make(map[string]interface{}, 2),
		WhereLikeCondition: make(map[string]string, 3),
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
func (q *NodeQueryOption) WithReady(status int8) *NodeQueryOption {
	q.whereEqCondition["ready"] = status
	return q
}
func (q *NodeQueryOption) WithInConditionCustom(column string, value interface{}) *NodeQueryOption {
	q.whereInCondition[column] = value
	return q
}
func (q *NodeQueryOption) WithNodeName(name string) *NodeQueryOption {
	q.whereEqCondition["host_name"] = name
	return q
}
func (q *NodeQueryOption) WithColumnFuzzyQuery(column, query string) *NodeQueryOption {
	q.WhereLikeCondition[column] = query
	return q
}
func (q *NodeQueryOption) WithIdList(idList []string) *NodeQueryOption {
	q.whereInCondition["id"] = idList
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
			db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.columnQuery.column), GetLikeExpr(queryOptions.columnQuery.query))
		}
		for column, val := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", column), GetLikeExpr(val))
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
	rctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var count int64
	notFound := false
	err := util.RetryWithBackoff(rctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rctx, 4*time.Second)
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
			db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.columnQuery.column), GetLikeExpr(queryOptions.columnQuery.query))
		}
		for column, val := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", column), GetLikeExpr(val))
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
	pgCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	var count int64

	db := rdb.WithContext(pgCtx).Model(&model.TensorContainer{}).Distinct("image")
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
		db = db.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), GetLikeExpr(query.columnQuery.query))
	}
	db = db.Where("status = ?", 0)
	err := db.Count(&count).Error
	if err == gorm.ErrRecordNotFound {
		return count, nil
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
			db = db.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), GetLikeExpr(query.columnQuery.query))
		}
		if limit > 0 && offset >= 0 {
			db = db.Offset(offset).Limit(limit)
		}
		return db.Distinct("image", "image_uuid").Find(&containers).Error
	})
	if err != nil {
		return nil, err
	}
	return containers, nil
}

func GetResourceContainersUniqueV2(ctx context.Context, rdb *gorm.DB, query *ResContainersQueryOption, offset, limit int) (containers []*model.TensorRawContainer, err error) {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	err = util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.TensorRawContainer{}).Where("status = ?", 0)
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
			db = db.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), GetLikeExpr(query.columnQuery.query))
		}
		if limit > 0 && offset >= 0 {
			db = db.Offset(offset).Limit(limit)
		}
		return db.Distinct("image_name", "image_uuid").Find(&containers).Error
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
			rdb = rdb.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), GetLikeExpr(query.columnQuery.query))
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
			rdb = rdb.Where(fmt.Sprintf("%s LIKE ?", query.columnQuery.column), GetLikeExpr(query.columnQuery.query))
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
		Status:        GetContainerStatus(&ContainerStatus.State),
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

func GetContainerStatus(status *corev1.ContainerState) int32 {
	if status.Waiting != nil && (status.Waiting.Reason != "" || status.Waiting.Message != "") {
		return waiting
	} else if status.Running != nil && !status.Running.StartedAt.IsZero() {
		return Running
	} else if status.Terminated != nil {
		return terminated
	}
	return waiting
}

func GetContainerCRIState(status *corev1.ContainerState, ready bool) int8 {
	//ref: k8s.io/kubernetes@v1.24.0/pkg/kubelet/kubelet_pods.go:1630
	if status.Running != nil && ready { //
		return ContainerStatus_normal_int
	}
	return ContainerStatus_abnormal_int
}

type colMultiQuery struct {
	column string
	query  []string
}

type RawContainersQueryOption struct {
	whereEqCondition     map[string]interface{}
	whereInCondition     map[string]interface{}
	wherePrefixCondition map[string]string
	columnQuery          colQuery
	columnQueries        []colMultiQuery
	prefixColumnQuery    colQuery
}

func RawContainersQuery() *RawContainersQueryOption {
	return &RawContainersQueryOption{
		whereEqCondition:     make(map[string]interface{}, 3),
		whereInCondition:     make(map[string]interface{}, 3),
		wherePrefixCondition: make(map[string]string),
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
func (q *RawContainersQueryOption) WithResourceName(ns string) *RawContainersQueryOption {
	q.whereEqCondition["resource_name"] = ns
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
func (q *RawContainersQueryOption) WithPrefixID(id string) *RawContainersQueryOption {
	q.wherePrefixCondition["id"] = id
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

func (q *RawContainersQueryOption) WithPrefixColumnQuery(column, query string) *RawContainersQueryOption {
	q.prefixColumnQuery.column = column
	q.prefixColumnQuery.query = query
	return q
}

// 精确匹配：status, k8s_managed, cluster_key
// 模糊匹配：node_name, namespace, pod_name, name, resource_name
// 范围匹配：updated_at
func (q *RawContainersQueryOption) OkForRedis() bool {
	if len(q.whereInCondition) != 1 {
		return false
	}
	// 只允许status<5的查询进入redis
	list, ok := q.whereInCondition["status"]
	if !ok {
		return false
	}
	ints := list.([]int)
	for _, status := range ints {
		if status >= assets.Exited {
			return false
		}
	}

	for f := range q.whereEqCondition {
		if f != "k8s_managed" && f != "node_name" && f != "namespace" && f != "pod_name" && f != "name" && f != "resource_name" && f != "cluster_key" {
			return false
		}
	}
	likeFileds := make([]string, 0)
	if q.columnQuery.column != "" {
		likeFileds = append(likeFileds, q.columnQuery.column)
	}
	if q.prefixColumnQuery.column != "" {
		likeFileds = append(likeFileds, q.prefixColumnQuery.column)
	}

	for _, column := range q.columnQueries {
		if column.column != "" {
			likeFileds = append(likeFileds, column.column)
		}
	}

	if len(likeFileds) == 0 {
		return false
	}

	for _, field := range likeFileds {
		if field != "node_name" && field != "namespace" && field != "pod_name" && field != "name" && field != "resource_name" {
			return false
		}
	}

	return true
}

func (q *RawContainersQueryOption) RedisRawQuery() string {
	if !q.OkForRedis() {
		return ""
	}

	builder := &strings.Builder{}
	status := make([]string, 0)

	// 状态
	v, ok := q.whereInCondition["status"]
	if ok {
		for _, s := range cast.ToIntSlice(v) {
			if s == assets.All {
				status = []string{}
				break
			}
			status = append(status, assets.GetRawContainerStatus(s))
		}
	}

	for f, v := range q.whereEqCondition {
		if f == "status" && cast.ToInt(v) < assets.Exited {
			status = append(status, assets.GetRawContainerStatus(cast.ToInt(v)))
			continue
		}
		vv := cast.ToString(v)
		if vv != "" {
			builder.WriteString(fmt.Sprintf("@%s:{%s} ", f, redisearch.EscapeTextFileString(vv)))
		}
	}

	if len(status) != 0 {
		builder.WriteString("@status:{")
		for i, s := range status {
			builder.WriteString(s)
			if i+1 != len(status) {
				builder.WriteByte('|')
			}
		}
		builder.WriteByte('}')
	}

	if q.columnQuery.column != "" && q.columnQuery.query != "" {
		builder.WriteString(fmt.Sprintf("@%s:{*%s*} ", q.columnQuery.column, redisearch.EscapeTextFileString(q.columnQuery.query)))
	}

	if q.prefixColumnQuery.column != "" && q.prefixColumnQuery.query != "" {
		builder.WriteString(fmt.Sprintf("@%s:{%s*} ", q.columnQuery.column, redisearch.EscapeTextFileString(q.columnQuery.query)))
	}

	for _, c := range q.columnQueries {
		if len(c.query) > 0 {
			builder.WriteString(fmt.Sprintf("@%s:{", c.column))
			for i, v := range c.query {
				builder.WriteString(fmt.Sprintf("*%s*", redisearch.EscapeTextFileString(v)))
				if i+1 != len(c.query) {
					builder.WriteByte('|')
				}
			}
			builder.WriteString("}")
		}
	}
	return strings.TrimSpace(builder.String())
}

func CountRawContainerWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, queryOptions *RawContainersQueryOption) (int64, error) {
	if !queryOptions.OkForRedis() {
		return CountRawContainer(ctx, rdb, queryOptions)
	}
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	rawQuery := queryOptions.RedisRawQuery()
	var cntNum int64

	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 4*time.Second)
		defer oneCancel()
		_, total, err := redisClient.Search(oneCtx, redisearch.NewQuery(rawQuery).Limit(0, 0))
		if err != nil {
			return err
		}

		cntNum = int64(total)
		return nil
	})

	return cntNum, err
}

func CountRawContainer(ctx context.Context, rdb *gorm.DB, queryOptions *RawContainersQueryOption) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 4*time.Second)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorRawContainer{})

		if len(queryOptions.whereEqCondition) > 0 {
			db = db.Where(queryOptions.whereEqCondition)
		}
		status, statusCondition := queryOptions.whereInCondition["status"]
		if len(queryOptions.whereInCondition) > 0 {
			if statusCondition && status == assets.All {
				delete(queryOptions.whereInCondition, "status")
			}
			for column, val := range queryOptions.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.columnQuery.column), GetLikeExpr(queryOptions.columnQuery.query))
		}
		if len(queryOptions.prefixColumnQuery.column) > 0 && len(queryOptions.prefixColumnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.prefixColumnQuery.column), fmt.Sprintf("%s%%", queryOptions.prefixColumnQuery.query))
		}
		if len(queryOptions.columnQueries) > 0 {
			for _, c := range queryOptions.columnQueries {
				if len(c.query) > 0 {
					if len(c.query) == 1 {
						db = db.Where(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(c.query[0]))
						continue
					}
					subQuery := rdb.WithContext(oneCtx).Model(&model.TensorRawContainer{}).Where(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(c.query[0]))
					for _, q := range c.query[1:] {
						subQuery = subQuery.Or(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(q))
					}
					db = db.Where(subQuery)
				}
			}
		}
		return db.Count(&cntNum).Error
	})

	return cntNum, err
}

func GetRawContainersWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, queryOptions *RawContainersQueryOption, offset int, limit int) ([]*model.TensorRawContainer, error) {
	if !queryOptions.OkForRedis() {
		return GetRawContainers(ctx, rdb, queryOptions, offset, limit)
	}
	var containers []*model.TensorRawContainer
	rawQuery := queryOptions.RedisRawQuery()

	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()

		result, _, err := redisClient.Search(oneCtx,
			redisearch.NewQuery(rawQuery).
				Limit(offset, limit).
				SetReturnFields("id").
				SetSortBy("id", true),
		)

		if err != nil {
			return err
		}

		containerIDs := make([]string, 0, len(result))

		for _, doc := range result {
			containerIDs = append(containerIDs, cast.ToString(doc.Properties["id"]))
		}
		if len(containerIDs) == 0 {
			return nil
		}

		return rdb.WithContext(oneCtx).
			Model(&model.TensorRawContainer{}).
			Where("id in ?", containerIDs).
			Order("id ASC").
			Find(&containers).Error
	})

	return containers, err
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
		if len(queryOptions.whereInCondition) > 0 {
			if statusCondition && status == assets.All {
				delete(queryOptions.whereInCondition, "status")
			}
			for column, val := range queryOptions.whereInCondition {
				db = db.Where(fmt.Sprintf("%s in ?", column), val)
			}
		}
		if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.columnQuery.column), GetLikeExpr(queryOptions.columnQuery.query))
		}
		if len(queryOptions.prefixColumnQuery.column) > 0 && len(queryOptions.prefixColumnQuery.query) > 0 {
			db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.prefixColumnQuery.column), fmt.Sprintf("%s%%", queryOptions.prefixColumnQuery.query))
		}

		for _, c := range queryOptions.columnQueries {
			if len(c.query) > 0 {
				if len(c.query) == 1 {
					db = db.Where(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(c.query[0]))
					continue
				}
				subQuery := rdb.WithContext(oneCtx).Model(&model.TensorRawContainer{}).Where(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(c.query[0]))
				for _, q := range c.query[1:] {
					subQuery = subQuery.Or(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(q))
				}
				db = db.Where(subQuery)
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

type RawContainersWithFrameworkQueryOption struct {
	WhereFrameworkLikeCondition map[string]string
	*RawContainersQueryOption
}

func RawContainersWithFrameworkQuery() *RawContainersWithFrameworkQueryOption {
	return &RawContainersWithFrameworkQueryOption{
		WhereFrameworkLikeCondition: make(map[string]string),
		RawContainersQueryOption:    RawContainersQuery(),
	}
}

func CountRawContainerWithFramework(ctx context.Context, rdb *gorm.DB, queryOptions *RawContainersWithFrameworkQueryOption) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cntNum int64
	var db *gorm.DB
	db = rdb.WithContext(ctx).Model(&model.TensorRawContainer{})
	if len(queryOptions.whereEqCondition) > 0 {
		db.Where(queryOptions.whereEqCondition)
	}
	status, statusCondition := queryOptions.whereInCondition["status"]
	if len(queryOptions.whereInCondition) > 0 {
		if statusCondition && status == assets.All {
			delete(queryOptions.whereInCondition, "status")
		}
		for column, val := range queryOptions.whereInCondition {
			db = db.Where(fmt.Sprintf("%s in ?", column), val)
		}
	}
	if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
		db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.columnQuery.column), GetLikeExpr(queryOptions.columnQuery.query))
	}
	if len(queryOptions.prefixColumnQuery.column) > 0 && len(queryOptions.prefixColumnQuery.query) > 0 {
		db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.prefixColumnQuery.column), fmt.Sprintf("%s%%", queryOptions.prefixColumnQuery.query))
	}
	for _, c := range queryOptions.columnQueries {
		if len(c.query) > 0 {
			if len(c.query) == 1 {
				db = db.Where(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(c.query[0]))
				continue
			}
			subQuery := rdb.WithContext(ctx).Model(&model.TensorRawContainer{}).Where(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(c.query[0]))
			for _, q := range c.query[1:] {
				subQuery = subQuery.Or(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(q))
			}
			db = db.Where(subQuery)
		}
	}

	if len(queryOptions.WhereFrameworkLikeCondition) > 0 {
		db = db.Joins("left join ivan_assets_raw_containers_frameworks f on ivan_assets_raw_containers.id = f.raw_container_id ")
		if len(queryOptions.WhereFrameworkLikeCondition) > 0 {
			for k, v := range queryOptions.WhereFrameworkLikeCondition {
				db = db.Where(k+" LIKE ?", GetLikeExpr(v))
			}
		}
		db.Distinct("ivan_assets_raw_containers.id")
	} else {
		db = db.Select("id")
	}
	err := db.Count(&cntNum).Error
	if err != nil {
		return 0, err
	}
	return cntNum, err
}

type RawContainerWithFramework struct {
	model.TensorRawContainer
	LanguageName     string `json:"languageName" gorm:"column:language_name"`
	FrameworkPath    string `json:"frameworkPath" gorm:"column:framework_path"`
	FrameworkName    string `json:"frameworkName" gorm:"column:framework_name"`
	FrameworkVersion string `json:"frameworkVersion" gorm:"column:framework_version"`
}
type RawContainerWithFrameworkStr struct {
	*model.TensorRawContainer
	FrameworkStr  string
	FrameworkPath string
	Tags          []string
}

func GetRawContainersWithFrameworkWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, queryOptions *RawContainersWithFrameworkQueryOption, offset int, limit int) ([]*RawContainerWithFrameworkStr, error) {
	if !queryOptions.OkForRedis() || len(queryOptions.WhereFrameworkLikeCondition) > 0 {
		return GetRawContainersWithFramework(ctx, rdb, queryOptions, offset, limit)
	}
	rawQuery := queryOptions.RedisRawQuery()

	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
	defer oneCancel()

	result, _, err := redisClient.Search(oneCtx,
		redisearch.NewQuery(rawQuery).
			Limit(offset, limit).
			SetReturnFields("id").
			SetSortBy("id", true),
	)

	if err != nil {
		return nil, err
	}

	containerIDs := make([]string, 0, len(result))
	for _, doc := range result {
		containerIDs = append(containerIDs, cast.ToString(doc.Properties["id"]))
	}
	if len(containerIDs) == 0 {
		return nil, nil
	}

	return getRawContainerWithFrameworkByIds(ctx, rdb, containerIDs, limit == 1)
}

func GetRawContainersWithFramework(ctx context.Context, rdb *gorm.DB, queryOptions *RawContainersWithFrameworkQueryOption, offset int, limit int) ([]*RawContainerWithFrameworkStr, error) {
	rCtx, cancel := context.WithTimeout(ctx, 8000*time.Millisecond)
	defer cancel()
	var containerIds []string
	var db *gorm.DB
	db = rdb.WithContext(rCtx).Model(&model.TensorRawContainer{})

	if len(queryOptions.whereEqCondition) > 0 {
		db.Where(queryOptions.whereEqCondition)
	}
	status, statusCondition := queryOptions.whereInCondition["status"]
	if len(queryOptions.whereInCondition) > 0 {
		if statusCondition && status == assets.All {
			delete(queryOptions.whereInCondition, "status")
		}
		for column, val := range queryOptions.whereInCondition {
			db = db.Where(fmt.Sprintf("%s in ?", column), val)
		}
	}

	for k, v := range queryOptions.wherePrefixCondition {
		db = db.Where(fmt.Sprintf("%s like '%s%%'", k, v))
	}

	if len(queryOptions.columnQuery.column) > 0 && len(queryOptions.columnQuery.query) > 0 {
		db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.columnQuery.column), GetLikeExpr(queryOptions.columnQuery.query))
	}
	if len(queryOptions.prefixColumnQuery.column) > 0 && len(queryOptions.prefixColumnQuery.query) > 0 {
		db = db.Where(fmt.Sprintf("%s LIKE ?", queryOptions.prefixColumnQuery.column), fmt.Sprintf("%s%%", queryOptions.prefixColumnQuery.query))
	}
	for _, c := range queryOptions.columnQueries {
		if len(c.query) > 0 {
			if len(c.query) == 1 {
				db = db.Where(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(c.query[0]))
				continue
			}
			subQuery := rdb.WithContext(ctx).Model(&model.TensorRawContainer{}).Where(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(c.query[0]))
			for _, q := range c.query[1:] {
				subQuery = subQuery.Or(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(q))
			}
			db = db.Where(subQuery)
		}
	}

	if len(queryOptions.WhereFrameworkLikeCondition) > 0 {
		db = db.Joins("left join ivan_assets_raw_containers_frameworks f on ivan_assets_raw_containers.id = f.raw_container_id ")
		if len(queryOptions.WhereFrameworkLikeCondition) > 0 {
			for k, v := range queryOptions.WhereFrameworkLikeCondition {
				db = db.Where(k+" LIKE ?", GetLikeExpr(v))
			}
		}
		db.Distinct("ivan_assets_raw_containers.id")
	} else {
		db = db.Select("id")
	}

	if offset >= 0 && limit >= 0 {
		db.Offset(offset).Limit(limit)
	}

	err := db.Order("id ASC").Scan(&containerIds).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}
	//
	if len(containerIds) == 0 {
		return nil, nil
	}
	return getRawContainerWithFrameworkByIds(ctx, rdb, containerIds, limit == 1)
}

func getRawContainerWithFrameworkByIds(ctx context.Context, rdb *gorm.DB, containerIds []string, isDetail bool) ([]*RawContainerWithFrameworkStr, error) {
	if len(containerIds) == 0 {
		return nil, nil
	}
	var containerWithF []*RawContainerWithFramework
	db := rdb.WithContext(ctx).Model(&model.TensorRawContainer{}).Select(" ivan_assets_raw_containers.* ,f.framework_name,f.framework_version,f.language_name,framework_path")
	db = db.Joins("left join ivan_assets_raw_containers_frameworks f on ivan_assets_raw_containers.id = f.raw_container_id ").
		Where("ivan_assets_raw_containers.id in ?", containerIds)

	err := db.Order("ivan_assets_raw_containers.id  ASC").Scan(&containerWithF).Error

	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}
	var containers []*RawContainerWithFrameworkStr
	idMap := make(map[string]struct{})

	buildDesc := func(withFramework *RawContainerWithFramework) string {
		if withFramework.FrameworkName == "" {
			if isDetail {
				return withFramework.LanguageName
			} else {
				return ""
			}
		}
		if withFramework.FrameworkVersion != "" {
			if isDetail {
				return fmt.Sprintf("%s(%s)-%s", withFramework.FrameworkName, withFramework.FrameworkVersion, withFramework.LanguageName)
			} else {
				return fmt.Sprintf("%s(%s)", withFramework.FrameworkName, withFramework.FrameworkVersion)
			}
		} else {
			if isDetail {
				return fmt.Sprintf("%s-%s", withFramework.FrameworkName, withFramework.LanguageName)
			} else {
				return withFramework.FrameworkName
			}
		}
	}

	for i, withFramework := range containerWithF {
		_, isOk := idMap[withFramework.ContainerID]
		if !isOk {
			elems := &RawContainerWithFrameworkStr{
				TensorRawContainer: &(containerWithF[i].TensorRawContainer),
			}
			elems.FrameworkStr = buildDesc(withFramework)
			elems.FrameworkPath = withFramework.FrameworkPath
			containers = append(containers, elems)
			idMap[withFramework.ContainerID] = struct{}{}
			continue
		}
		frameworkStr := buildDesc(withFramework)
		if containers[len(containers)-1].FrameworkStr != "" && frameworkStr != "" {
			containers[len(containers)-1].FrameworkStr += " , "
		}
		containers[len(containers)-1].FrameworkStr += frameworkStr

		if isDetail {
			frameworkPath := withFramework.FrameworkPath
			if containers[len(containers)-1].FrameworkPath != "" && frameworkPath != "" {
				containers[len(containers)-1].FrameworkPath += " , "
			}
			containers[len(containers)-1].FrameworkPath += frameworkPath
		}
	}
	return containers, nil
}

func UpsertRawContainerWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, container *assets.TensorRawContainer) error {
	rCtx, cancel := context.WithTimeout(ctx, 15000*time.Millisecond)
	defer cancel()

	logging.GetLogger().Info().Msgf("on triggering upsert raw container to db and redis, container: %s", container.ContainerID)

	doc := redisearch.NewDocument(fmt.Sprintf("rawContainer:%s", container.ContainerID), 1).
		Set("id", container.ContainerID).
		Set("status", assets.GetRawContainerStatus(int(container.Status))).
		Set("cluster_key", container.ClusterKey).
		Set("k8s_managed", strconv.FormatBool(container.K8sManaged)).
		Set("node_name", container.NodeName).
		Set("namespace", container.Namespace).
		Set("pod_name", container.PodName).
		Set("name", container.Name).
		Set("resource_name", container.ResourceName).
		Set("updated_at", container.UpdatedAt.UnixMilli())

	containerUUId := util.GenerateUUID(container.ContainerID)
	return rdb.WithContext(rCtx).Transaction(func(tx *gorm.DB) error {
		err := upsertRawContainersWithTx(tx, container)
		if err != nil {
			return err
		}
		if container.Status >= assets.Exited {
			logging.GetLogger().Info().Msgf("container status %d, delete rawContainer: %s from redis", container.ContainerID, doc.Id)
			err = deleteResourceImageByRawContainer(rCtx, redisClient, []uint32{containerUUId})
			if err != nil {
				return err
			}
			return redisClient.DeleteDoc(rCtx, doc.Id)
		} else {
			logging.GetLogger().Info().Msgf("upsert rawContainer: %s to redis", doc.Id)
			err = addResourceImageByRawContainer(rCtx, redisClient, containerUUId, container.ImageUUID)
			if err != nil {
				return err
			}
			return redisClient.AddDoc(rCtx, doc)
		}
	})
}

func UpsertRawContainers(ctx context.Context, rdb *gorm.DB, container *assets.TensorRawContainer) error {
	rCtx, cancel := context.WithTimeout(ctx, 15000*time.Millisecond)
	defer cancel()
	return rdb.WithContext(rCtx).Transaction(func(tx *gorm.DB) error {
		return upsertRawContainersWithTx(tx, container)
	})
}

func upsertRawContainersWithTx(tx *gorm.DB, container *assets.TensorRawContainer) error {
	var svcList []*model.TensorRawContainerSvc
	var frameworkList []*model.TensorRawContainerFramework
	if container.Discovery != nil {
		svcList, frameworkList = getModelFromRawContainer(container)
	}
	rawContainer := container.TensorRawContainer
	if rawContainer.LastStopTime.IsZero() {
		rawContainer.LastStopTime = rawContainer.CreatedAt
	}
	err := tx.Model(&model.TensorRawContainer{}).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(OnDupUpdatedColsForRawContainer),
	}).Create(rawContainer).Error
	if err != nil {
		return err
	}
	if len(svcList) > 0 {
		err = tx.Model(&model.TensorRawContainerSvc{}).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "id"}}, DoUpdates: clause.AssignmentColumns(OnDupUpdatedColsForRawCtnSvc)}).Create(&svcList).Error
		if err != nil {
			return err
		}
	}
	if len(frameworkList) > 0 {
		err = tx.Model(&model.TensorRawContainerFramework{}).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "id"}}, DoUpdates: clause.AssignmentColumns(OnDupUpdatedColsForRawCtnFramework)}).Create(&frameworkList).Error
		if err != nil {
			return err
		}
	}
	return nil
}

func getModelFromRawContainer(container *assets.TensorRawContainer) ([]*model.TensorRawContainerSvc, []*model.TensorRawContainerFramework) {
	if container.Discovery == nil {
		return nil, nil
	}
	var svcList []*model.TensorRawContainerSvc
	var frameworkList []*model.TensorRawContainerFramework
	updateTime := container.UpdatedAt
	for _, service := range container.Discovery.Services {
		svc := &model.TensorRawContainerSvc{
			TableBase: model.TableBase{
				ID:        util.GenerateUUID(container.ContainerID, service.Name),
				CreatedAt: updateTime,
				UpdatedAt: updateTime,
			},
			PodName:        container.PodName,
			RawContainerID: container.ContainerID,
			SvcName:        service.Name,
			SvcVersion:     service.Version,
			SvcType:        getSvcType(service.Name),
			User:           container.User,
			UserGroup:      "-",
			Cmd:            service.Cmd,
			Port:           service.Port,
			RootDir:        service.RootDir,
			BinaryDir:      service.BinaryDir,
			ConfigDir:      service.ConfigDir,
			DataDir:        service.DataDir,
			LogDir:         service.LogDir,
		}
		svcList = append(svcList, svc)
	}

	for _, framework := range container.Discovery.Frameworks {
		frame := &model.TensorRawContainerFramework{
			TableBase: model.TableBase{
				ID:        util.GenerateUUID(container.ContainerID, framework.LanguageName, framework.FrameworkName),
				CreatedAt: updateTime,
				UpdatedAt: updateTime,
			},
			RawContainerID:   container.ContainerID,
			LanguageName:     framework.LanguageName,
			LanguageVersion:  framework.LanguageVersion,
			LanguageBinPath:  framework.LanguageBinPath,
			FrameworkPath:    framework.FrameworkPath,
			FrameworkName:    framework.FrameworkName,
			FrameworkVersion: framework.FrameworkVersion,
		}
		frameworkList = append(frameworkList, frame)
	}
	return svcList, frameworkList
}

func getSvcType(svcName string) string {
	svcType := assets.BusiSvcTypeMap[svcName]
	if svcType == "" {
		svcType = "未知"
	}
	return svcType
}

// ingress
func CountIngress(ctx context.Context, rdb *gorm.DB, queryOptions *IngressesQueryOption) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 4*time.Second)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorIngress{})

		if len(queryOptions.whereEqCondition) > 0 {
			db = db.Where(queryOptions.whereEqCondition)
		}
		for k, v := range queryOptions.whereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.whereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		if !queryOptions.timeRange.start.IsZero() {
			db = db.Where("created_at > ?", queryOptions.timeRange.start)
		}
		if !queryOptions.timeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.timeRange.end)
		}
		db = db.Where("status=0")

		return db.Count(&cntNum).Error
	})

	return cntNum, err
}

func GetIngresses(ctx context.Context, rdb *gorm.DB, queryOptions *IngressesQueryOption, offset int, limit int) ([]*model.TensorIngress, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	var ingresses []*model.TensorIngress
	notFound := false
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorIngress{})

		if len(queryOptions.whereEqCondition) > 0 {
			db.Where(queryOptions.whereEqCondition)
		}
		for k, v := range queryOptions.whereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.whereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		db = db.Where("status=0")
		if !queryOptions.timeRange.start.IsZero() {
			db = db.Where("created_at > ?", queryOptions.timeRange.start)
		}
		if !queryOptions.timeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.timeRange.end)
		}

		if offset >= 0 && limit >= 0 {
			db.Offset(offset).Limit(limit)
		}
		err := db.Order("id ASC").Find(&ingresses).Error
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
	return ingresses, nil
}

type IngressesQueryOption struct {
	whereEqCondition   map[string]interface{}
	whereInCondition   map[string]interface{}
	whereLikeCondition map[string]string
	timeRange          TimeRange
}

func IngressesQuery() *IngressesQueryOption {
	return &IngressesQueryOption{
		whereEqCondition:   make(map[string]interface{}),
		whereLikeCondition: make(map[string]string),
		whereInCondition:   make(map[string]interface{}),
	}
}

func (q *IngressesQueryOption) WithCluster(clusterKey string) *IngressesQueryOption {
	q.whereEqCondition["cluster_key"] = clusterKey
	return q
}
func (q *IngressesQueryOption) WithClusterList(clusterKeyList []string) *IngressesQueryOption {
	q.whereInCondition["cluster_key"] = clusterKeyList
	return q
}

func (q *IngressesQueryOption) WithNamespace(ns string) *IngressesQueryOption {
	q.whereEqCondition["namespace"] = ns
	return q
}
func (q *IngressesQueryOption) WithFuzzNamespace(ns string) *IngressesQueryOption {
	q.whereLikeCondition["namespace"] = ns
	return q
}
func (q *IngressesQueryOption) WithIdList(idList []string) *IngressesQueryOption {
	q.whereInCondition["id"] = idList
	return q
}
func (q *IngressesQueryOption) WithFuzzName(name string) *IngressesQueryOption {
	q.whereLikeCondition["name"] = name
	return q
}
func (q *IngressesQueryOption) WithName(name string) *IngressesQueryOption {
	q.whereEqCondition["name"] = name
	return q
}
func (q *IngressesQueryOption) WithTimeRange(start, end time.Time) *IngressesQueryOption {
	q.timeRange.start = start
	q.timeRange.end = end
	return q
}

func GetIngressBackendKinds(ctx context.Context, rdb *gorm.DB) ([]string, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	notFound := false
	var kindList []string
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()
		err := rdb.WithContext(oneCtx).Model(&model.TensorIngressRule{}).Where(" status =0 ").
			Distinct("backend_kind").Scan(&kindList).Error
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
	return kindList, nil
}

type IngressesRuleQueryOption struct {
	whereEqCondition   map[string]interface{}
	whereLikeCondition map[string]string
	whereInCondition   map[string]interface{}
	query              mulColQuery
}

func NewIngressesRuleQuery() *IngressesRuleQueryOption {
	return &IngressesRuleQueryOption{
		whereEqCondition:   make(map[string]interface{}),
		whereLikeCondition: make(map[string]string),
		whereInCondition:   make(map[string]interface{}),
	}
}

func (i *IngressesRuleQueryOption) WithQuery(query string, columns []string) {
	if len(query) == 0 || len(columns) == 0 {
		return
	}
	i.query = mulColQuery{
		columns: columns,
		query:   query,
	}
}
func (i *IngressesRuleQueryOption) WithBackendKind(backendKinds []string) {
	if len(backendKinds) == 0 {
		return
	}
	i.whereInCondition["backend_kind"] = backendKinds
}
func (i *IngressesRuleQueryOption) WithPathType(pathTypes []string) {
	if len(pathTypes) == 0 {
		return
	}
	i.whereInCondition["path_type"] = pathTypes
}
func (i *IngressesRuleQueryOption) WithIngressId(ingressId int64) {
	i.whereEqCondition["ingress_id"] = ingressId
}

func CountIngressRule(ctx context.Context, rdb *gorm.DB, queryOptions *IngressesRuleQueryOption) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 4*time.Second)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorIngressRule{})

		if len(queryOptions.whereEqCondition) > 0 {
			db = db.Where(queryOptions.whereEqCondition)
		}
		for k, v := range queryOptions.whereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.whereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		if queryOptions.query.query != "" {
			var sql string
			expr := GetLikeExpr(queryOptions.query.query)
			for i := 0; i < len(queryOptions.query.columns); i++ {
				if i != 0 {
					sql += " OR "
				}
				sql += fmt.Sprintf("%s like '%s'", queryOptions.query.columns[i], expr)
			}
			db = db.Where(sql)
		}

		db = db.Where("status=0")

		return db.Count(&cntNum).Error
	})

	return cntNum, err
}

func GetIngressRules(ctx context.Context, rdb *gorm.DB, queryOptions *IngressesRuleQueryOption, offset int, limit int) ([]*model.TensorIngressRule, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	var ingressRules []*model.TensorIngressRule
	notFound := false
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorIngressRule{})

		if len(queryOptions.whereEqCondition) > 0 {
			db.Where(queryOptions.whereEqCondition)
		}
		for k, v := range queryOptions.whereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.whereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		if queryOptions.query.query != "" {
			var sql string
			expr := GetLikeExpr(queryOptions.query.query)
			for i := 0; i < len(queryOptions.query.columns); i++ {
				if i != 0 {
					sql += " OR "
				}
				sql += fmt.Sprintf("%s like '%s'", queryOptions.query.columns[i], expr)
			}
			db = db.Where(sql)
		}
		db = db.Where("status=0")
		if offset >= 0 && limit >= 0 {
			db.Offset(offset).Limit(limit)
		}
		err := db.Order("id ASC").Find(&ingressRules).Error
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
	return ingressRules, nil

}

type IngressDetail struct {
	model.TensorIngress
	Rules []model.TensorIngressRule
}

func UpsertIngresses(ctx context.Context, rdb *gorm.DB, ingress *netv1.Ingress, clusterKey string, updateTime time.Time) (uint32, error) {
	detail, createErr := newModelFromIngress(ingress, clusterKey, updateTime)
	if createErr != nil || detail == nil {
		return 0, createErr
	}

	tctx, cancel := context.WithTimeout(ctx, 5000*time.Millisecond)
	defer cancel()

	err := rdb.WithContext(tctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Model(&model.TensorIngress{}).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns(OnDupUpdatedColsForIngress),
		}).Create(&detail.TensorIngress).Error
		if err != nil {
			return err
		}
		if len(detail.Rules) > 0 {
			err = tx.Model(&model.TensorIngressRule{}).Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "id"}},
				DoUpdates: clause.AssignmentColumns(OnDupUpdatedColsForIngressRule),
			}).Create(&detail.Rules).Error
		}
		if err != nil {
			return err
		}
		deleteTime := updateTime.Add(time.Second * time.Duration(-1))
		return tx.Where("ingress_id=? and updated_at < ?", detail.ID, deleteTime).Delete(&model.TensorIngressRule{}).Error
	})

	return detail.ID, err
}

func SoftDeleteIngress(ctx context.Context, rdb *gorm.DB, ingress *netv1.Ingress, clusterKey string, updateTime time.Time) error {
	tctx, cancel := context.WithTimeout(ctx, 3000*time.Millisecond)
	defer cancel()

	uuid := util.GenerateUUID(clusterKey, ingress.Namespace, ingress.Name)
	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(tctx, 1000*time.Millisecond)
		defer cancel()

		err := rdb.WithContext(oneCtx).Transaction(func(tx *gorm.DB) error {
			err := tx.Model(&model.TensorIngress{}).Where("id = ?", uuid).Updates(map[string]interface{}{
				"status":     1,
				"updated_at": updateTime,
			}).Error
			if err != nil {
				return err
			}
			return tx.Where("ingress_id = ?", uuid).Delete(&model.TensorIngressRule{}).Error
		})
		return err
	})
}

func newModelFromIngress(ingress *netv1.Ingress, clusterKey string, updateTime time.Time) (*IngressDetail, error) {
	detail := &IngressDetail{}
	detail.ID = util.GenerateUUID(clusterKey, ingress.Namespace, ingress.Name)
	detail.CreatedAt = ingress.CreationTimestamp.Time
	detail.UpdatedAt = updateTime
	detail.Name = ingress.Name
	detail.Namespace = ingress.Namespace
	detail.ClusterKey = clusterKey
	detail.UID = string(ingress.UID)

	tlsMap := make(map[string]struct{})
	for _, tl := range ingress.Spec.TLS {
		for _, t := range tl.Hosts {
			tlsMap[t] = struct{}{}
		}
	}

	for _, rule := range ingress.Spec.Rules {
		for _, path := range rule.HTTP.Paths {
			tmp := model.TensorIngressRule{
				TableBase: model.TableBase{
					ID:        util.GenerateUUID(clusterKey, ingress.Namespace, ingress.Name, rule.Host, path.Path),
					CreatedAt: updateTime,
					UpdatedAt: updateTime,
				},
				IngressId: detail.ID,
				Host:      rule.Host,
				Path:      path.Path,
				Protocol:  "HTTP",
			}
			if _, isOK := tlsMap[rule.Host]; isOK {
				tmp.Protocol = "HTTPS"
			}
			if path.PathType != nil {
				tmp.PathType = string(*path.PathType)
			}
			if path.Backend.Service != nil {
				tmp.BackendKind = "Service"
				tmp.BackendApiGroup = "V1"
				tmp.BackendName = path.Backend.Service.Name
				tmp.ServicePort = strconv.Itoa(int(path.Backend.Service.Port.Number))
				if tmp.ServicePort == "0" {
					tmp.ServicePort = "-"
				}
			} else if path.Backend.Resource != nil {
				tmp.BackendKind = path.Backend.Resource.Kind
				if path.Backend.Resource.APIGroup != nil {
					tmp.BackendApiGroup = *path.Backend.Resource.APIGroup
				}
				tmp.BackendName = path.Backend.Resource.Name
			}
			tmp.WebDesc = fmt.Sprintf("%s%s", tmp.Host, tmp.Path)
			detail.Rules = append(detail.Rules, tmp)
		}
	}
	return detail, nil
}

func CleanUpUnUpdatedIngresses(ctx context.Context, rdb *gorm.DB, ts time.Time, clusterKey string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return rdb.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var ingressIds []uint32
		err := tx.Model(&model.TensorIngress{}).Where("updated_at < ? AND status = ? AND cluster_key = ?", ts, 0, clusterKey).Select("id").Scan(&ingressIds).Error
		if err != nil {
			return err
		}
		if len(ingressIds) == 0 {
			return nil
		}
		err = tx.Model(&model.TensorIngress{}).Where("id in ?", ingressIds).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": ts,
		}).Error
		if err != nil {
			return err
		}
		return tx.Where("updated_at < ?  AND  ingress_id in ?", ts, ingressIds).Delete(&model.TensorIngressRule{}).Error
	})
}

type ServicesQueryOption struct {
	whereEqCondition   map[string]interface{}
	whereLikeCondition map[string]string
	whereInCondition   map[string]interface{}
	timeRange          TimeRange
}

func ServicesQuery() *ServicesQueryOption {
	return &ServicesQueryOption{
		whereEqCondition:   make(map[string]interface{}),
		whereLikeCondition: make(map[string]string),
		whereInCondition:   make(map[string]interface{}),
	}
}

func (q *ServicesQueryOption) WithCluster(clusterKey string) *ServicesQueryOption {
	q.whereEqCondition["cluster_key"] = clusterKey
	return q
}
func (q *ServicesQueryOption) WithClusterList(clusterKeyList []string) *ServicesQueryOption {
	q.whereInCondition["cluster_key"] = clusterKeyList
	return q
}

func (q *ServicesQueryOption) WithNamespace(ns string) *ServicesQueryOption {
	q.whereEqCondition["namespace"] = ns
	return q
}
func (q *ServicesQueryOption) WithFuzzNamespace(ns string) *ServicesQueryOption {
	q.whereLikeCondition["namespace"] = ns
	return q
}
func (q *ServicesQueryOption) WithFuzzName(name string) *ServicesQueryOption {
	q.whereLikeCondition["name"] = name
	return q
}
func (q *ServicesQueryOption) WithName(name string) *ServicesQueryOption {
	q.whereEqCondition["name"] = name
	return q
}
func (q *ServicesQueryOption) WithClusterIp(ip string) {
	q.whereLikeCondition["cluster_ip"] = ip
}
func (q *ServicesQueryOption) WithServiceTypes(types []string) {
	q.whereInCondition["type"] = types
}
func (q *ServicesQueryOption) WithIdList(idList []string) {
	q.whereInCondition["id"] = idList
}
func (q *ServicesQueryOption) WithTimeRange(start, end time.Time) *ServicesQueryOption {
	q.timeRange.start = start
	q.timeRange.end = end
	return q
}

type ServicesListBase struct {
	Id         int       // id: cluster_key/namespace/Name
	Name       string    `json:"name"`
	Namespace  string    ` json:"namespace"`
	ClusterKey string    ` json:"clusterKey"`
	PortsStr   string    `json:"portsStr"`
	Type       string    `json:"type"`
	ClusterIp  string    `json:"clusterIp"`
	CreatedAt  time.Time `json:"createdAt"`
}

func CountService(ctx context.Context, rdb *gorm.DB, queryOptions *ServicesQueryOption) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 4*time.Second)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorService{})

		if len(queryOptions.whereEqCondition) > 0 {
			db = db.Where(queryOptions.whereEqCondition)
		}
		for k, v := range queryOptions.whereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.whereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		if !queryOptions.timeRange.start.IsZero() {
			db = db.Where("created_at > ?", queryOptions.timeRange.start)
		}
		if !queryOptions.timeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.timeRange.end)
		}

		db = db.Where("status=0")

		return db.Count(&cntNum).Error
	})

	return cntNum, err
}

func GetService(ctx context.Context, rdb *gorm.DB, queryOptions *ServicesQueryOption, offset int, limit int) ([]*model.TensorService, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	var services []*model.TensorService
	notFound := false
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorService{})

		if len(queryOptions.whereEqCondition) > 0 {
			db.Where(queryOptions.whereEqCondition)
		}
		for k, v := range queryOptions.whereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.whereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		db = db.Where("status=0")
		if !queryOptions.timeRange.start.IsZero() {
			db = db.Where("created_at > ?", queryOptions.timeRange.start)
		}
		if !queryOptions.timeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.timeRange.end)
		}

		if offset >= 0 && limit >= 0 {
			db.Offset(offset).Limit(limit)
		}
		err := db.Order("id ASC").Find(&services).Error
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
	return services, nil
}

func UpsertService(ctx context.Context, rdb *gorm.DB, svc *corev1.Service, clusterKey string, updateTime time.Time) (uint32, error) {
	s, createErr := newModelFromService(svc, clusterKey, updateTime)
	if createErr != nil || s == nil {
		return 0, createErr
	}

	rCtx, cancel := context.WithTimeout(ctx, 5000*time.Millisecond)
	defer cancel()

	err := rdb.WithContext(rCtx).Model(&model.TensorService{}).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(OnDupUpdatedColsForService),
	}).Create(s).Error
	if err != nil {
		return 0, err
	}
	return s.ID, nil
}

func SoftDeleteService(ctx context.Context, rdb *gorm.DB, svc *corev1.Service, clusterKey string, updateTime time.Time) error {
	tctx, cancel := context.WithTimeout(ctx, 3000*time.Millisecond)
	defer cancel()

	uuid := util.GenerateUUID(clusterKey, svc.Namespace, svc.Name)
	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(tctx, 1000*time.Millisecond)
		defer cancel()
		return rdb.WithContext(oneCtx).Model(&model.TensorService{}).Where("id = ?", uuid).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": updateTime,
		}).Error
	})
}

func newModelFromService(svc *corev1.Service, clusterKey string, updateTime time.Time) (*model.TensorService, error) {
	var ports []model.ServicePort
	var portStr []string
	for _, port := range svc.Spec.Ports {
		portStr = append(portStr, fmt.Sprintf("%d/%s", port.Port, port.Protocol))
		ports = append(ports, model.ServicePort{
			Name:        port.Name,
			Protocol:    string(port.Protocol),
			AppProtocol: port.AppProtocol,
			Port:        strconv.Itoa(int(port.Port)),
			TargetPort:  port.TargetPort.String(),
			NodePort:    strconv.Itoa(int(port.NodePort)),
		})
	}
	result := &model.TensorService{
		TableBase: model.TableBase{
			ID:        util.GenerateUUID(clusterKey, svc.Namespace, svc.Name),
			CreatedAt: svc.CreationTimestamp.Time,
			UpdatedAt: updateTime,
		},
		Name:       svc.Name,
		Namespace:  svc.Namespace,
		ClusterKey: clusterKey,
		UID:        string(svc.UID),
		Labels:     svc.Labels,
		Type:       string(svc.Spec.Type),
		ClusterIp:  svc.Spec.ClusterIP,
		PortsStr:   strings.Join(portStr, ","),
		Ports:      ports,
		Selector:   svc.Spec.Selector,
	}
	if result.ClusterIp == "None" {
		result.ClusterIp = ""
	}
	return result, nil

}

func CleanUpUnUpdatedServices(ctx context.Context, rdb *gorm.DB, t time.Time, clusterKey string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
		defer cancel()
		logging.GetLogger().Info().Msgf("CleanUpUnUpdatedServices 清理更新时间小于%v的记录", t)
		return rdb.WithContext(oneCtx).Model(&model.TensorService{}).Where("updated_at < ? AND status = ? AND cluster_key = ?", t, 0, clusterKey).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": t,
		}).Error
	})
}

type EndpointsQueryOption struct {
	WhereEqCondition   map[string]interface{}
	WhereInCondition   map[string]interface{}
	WhereLikeCondition map[string]string
	TimeRange          TimeRange
}

func EndpointsQuery() *EndpointsQueryOption {
	return &EndpointsQueryOption{
		WhereEqCondition:   make(map[string]interface{}),
		WhereLikeCondition: make(map[string]string),
		WhereInCondition:   make(map[string]interface{}),
	}
}
func (q *EndpointsQueryOption) WithTimeRange(start, end time.Time) *EndpointsQueryOption {
	q.TimeRange.start = start
	q.TimeRange.end = end
	return q
}

func CountEndpoints(ctx context.Context, rdb *gorm.DB, queryOptions *EndpointsQueryOption) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 4*time.Second)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorEndpoints{})

		if len(queryOptions.WhereEqCondition) > 0 {
			db = db.Where(queryOptions.WhereEqCondition)
		}
		for k, v := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.WhereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		if !queryOptions.TimeRange.start.IsZero() {
			db = db.Where("created_at > ?", queryOptions.TimeRange.start)
		}
		if !queryOptions.TimeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.TimeRange.end)
		}
		db = db.Where("status=0")

		return db.Count(&cntNum).Error
	})

	return cntNum, err
}

func GetEndpoints(ctx context.Context, rdb *gorm.DB, queryOptions *EndpointsQueryOption, offset int, limit int) ([]*model.TensorEndpoints, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	var endpoints []*model.TensorEndpoints
	notFound := false
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorEndpoints{})

		if len(queryOptions.WhereEqCondition) > 0 {
			db.Where(queryOptions.WhereEqCondition)
		}
		for k, v := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.WhereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		db = db.Where("status=0")
		if !queryOptions.TimeRange.start.IsZero() {
			db = db.Where("created_at > ?", queryOptions.TimeRange.start)
		}
		if !queryOptions.TimeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.TimeRange.end)
		}
		if offset >= 0 && limit >= 0 {
			db.Offset(offset).Limit(limit)
		}
		err := db.Order("id ASC").Find(&endpoints).Error
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
	return endpoints, nil

}

func GetEndpointSubsetKinds(ctx context.Context, rdb *gorm.DB) ([]string, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	notFound := false
	var kindList []string
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()
		err := rdb.WithContext(oneCtx).Model(&model.TensorEndpointsSubset{}).Where(" status =0 ").
			Distinct("target_ref_kind").Scan(&kindList).Error
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
	return kindList, nil
}

type EndpointsSubsetsQueryOption struct {
	WhereEqCondition   map[string]interface{}
	WhereLikeCondition map[string]string
	WhereInCondition   map[string]interface{}
}

func EndpointsSubsetsQuery() *EndpointsSubsetsQueryOption {
	return &EndpointsSubsetsQueryOption{
		WhereEqCondition:   make(map[string]interface{}),
		WhereLikeCondition: make(map[string]string),
		WhereInCondition:   make(map[string]interface{}),
	}
}

func CountEndpointsSubsets(ctx context.Context, rdb *gorm.DB, queryOptions *EndpointsSubsetsQueryOption) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 4*time.Second)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorEndpointsSubset{})

		if len(queryOptions.WhereEqCondition) > 0 {
			db = db.Where(queryOptions.WhereEqCondition)
		}
		for k, v := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.WhereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		db = db.Where("status=0")
		return db.Count(&cntNum).Error
	})

	return cntNum, err
}

func GetEndpointSubsets(ctx context.Context, rdb *gorm.DB, queryOptions *EndpointsSubsetsQueryOption, offset int, limit int) ([]*model.TensorEndpointsSubset, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	var ingressRules []*model.TensorEndpointsSubset
	notFound := false
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorEndpointsSubset{})

		if len(queryOptions.WhereEqCondition) > 0 {
			db.Where(queryOptions.WhereEqCondition)
		}
		for k, v := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.WhereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		db = db.Where("status=0")
		if offset >= 0 && limit >= 0 {
			db.Offset(offset).Limit(limit)
		}
		err := db.Order("id ASC").Find(&ingressRules).Error
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
	return ingressRules, nil
}

func UpsertEndpoints(ctx context.Context, rdb *gorm.DB, endpoints *assets.EndpointsTmp, clusterKey string, updateTime time.Time) (uint32, error) {
	rCtx, cancel := context.WithTimeout(ctx, 5000*time.Millisecond)
	defer cancel()

	endpointsDetail := newModeFromEndpoints(endpoints, clusterKey, updateTime)
	err := rdb.WithContext(rCtx).Transaction(func(tx *gorm.DB) error {
		err := tx.Model(&model.TensorEndpoints{}).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns(OnDupUpdatedColsForEndpoint),
		}).Create(endpointsDetail.TensorEndpoints).Error
		if err != nil {
			return err
		}
		if len(endpointsDetail.Subsets) > 0 {
			err = tx.Model(&model.TensorEndpointsSubset{}).Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "id"}},
				DoUpdates: clause.AssignmentColumns(OnDupUpdatedColsForEndpointSubset),
			}).Create(&endpointsDetail.Subsets).Error
		}
		if err != nil {
			return err
		}
		deleteTime := updateTime.Add(time.Second * time.Duration(-1))
		return tx.Where("endpoints_id =? and updated_at < ?", endpointsDetail.ID, deleteTime).Delete(&model.TensorEndpointsSubset{}).Error
	})
	if err != nil {
		return 0, err
	}
	return endpointsDetail.ID, nil
}

func SoftDeleteEndpoints(ctx context.Context, rdb *gorm.DB, endpoints *assets.EndpointsTmp, clusterKey string, updateTime time.Time) error {
	tctx, cancel := context.WithTimeout(ctx, 3000*time.Millisecond)
	defer cancel()

	uuid := util.GenerateUUID(clusterKey, endpoints.Namespace, endpoints.Name)
	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(tctx, 1000*time.Millisecond)
		defer cancel()

		err := rdb.WithContext(oneCtx).Transaction(func(tx *gorm.DB) error {
			err := tx.Model(&model.TensorEndpoints{}).Where("id = ?", uuid).Updates(map[string]interface{}{
				"status":     1,
				"updated_at": updateTime,
			}).Error
			if err != nil {
				return err
			}
			return tx.Where("endpoints_id = ?", uuid).Delete(&model.TensorEndpointsSubset{}).Error
		})
		return err
	})
}

type EndpointsDetail struct {
	*model.TensorEndpoints
	Subsets []model.TensorEndpointsSubset
}

func newModeFromEndpoints(endpoints *assets.EndpointsTmp, clusterKey string, updateTime time.Time) *EndpointsDetail {
	detail := EndpointsDetail{
		TensorEndpoints: &model.TensorEndpoints{
			TableBase: model.TableBase{
				ID:        util.GenerateUUID(clusterKey, endpoints.Namespace, endpoints.Name),
				CreatedAt: endpoints.CreationTimestamp.Time,
				UpdatedAt: updateTime,
			},
			Name:        endpoints.Name,
			Namespace:   endpoints.Namespace,
			ClusterKey:  clusterKey,
			ServiceName: endpoints.ServiceName,
			UID:         string(endpoints.UID),
		},
	}
	newSubsetFunc := func(address corev1.EndpointAddress, isReady bool, ports string) model.TensorEndpointsSubset {
		tmp := model.TensorEndpointsSubset{
			TableBase: model.TableBase{
				ID:        util.GenerateUUID(clusterKey, endpoints.Namespace, endpoints.Name, address.IP),
				CreatedAt: updateTime,
				UpdatedAt: updateTime,
			},
			EndpointsId: detail.ID,
			Ip:          address.IP,
		}
		if isReady {
			tmp.AddressStatus = "Ready"
		} else {
			tmp.AddressStatus = "NotReady"
		}
		if address.NodeName != nil {
			tmp.NodeName = *address.NodeName
		}
		if address.TargetRef != nil {
			tmp.TargetRefKind = address.TargetRef.Kind
			tmp.Name = address.TargetRef.Name
			tmp.NameSpace = address.TargetRef.Namespace
		}
		tmp.Ports = ports
		return tmp
	}

	for _, subset := range endpoints.Subsets {
		var portsStr string
		builder := strings.Builder{}
		for i, port := range subset.Ports {
			builder.WriteString(fmt.Sprintf("%d/%s", int(port.Port), string(port.Protocol)))
			if i != len(subset.Ports)-1 {
				builder.WriteString(" , ")
			}
		}
		portsStr = builder.String()
		for _, address := range subset.Addresses {
			tmp := newSubsetFunc(address, true, portsStr)
			detail.Subsets = append(detail.Subsets, tmp)
		}
		for _, address := range subset.NotReadyAddresses {
			tmp := newSubsetFunc(address, false, portsStr)
			detail.Subsets = append(detail.Subsets, tmp)
		}
	}
	return &detail
}

func CleanUpUnUpdatedEndpoints(ctx context.Context, rdb *gorm.DB, ts time.Time, clusterKey string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
		defer cancel()

		return rdb.WithContext(oneCtx).Transaction(func(tx *gorm.DB) error {
			var endIds []int32
			err := tx.Model(&model.TensorEndpoints{}).Where("updated_at < ? AND status = ? AND cluster_key = ?", ts, 0, clusterKey).Select("id").Scan(&endIds).Error
			if err != nil {
				return err
			}
			if len(endIds) == 0 {
				return nil
			}
			err = tx.Model(&model.TensorEndpoints{}).Where("id in ?", endIds).Updates(map[string]interface{}{
				"status":     1,
				"updated_at": ts,
			}).Error
			if err != nil {
				return err
			}
			return tx.Where("updated_at < ?  AND  endpoints_id in ?", ts, endIds).Delete(&model.TensorEndpointsSubset{}).Error
		})
	})
}

type SecretsQueryOption struct {
	WhereEqCondition   map[string]interface{}
	WhereInCondition   map[string]interface{}
	WhereLikeCondition map[string]string
	TimeRange          TimeRange
}

func (s *SecretsQueryOption) WithTimeRange(start, end time.Time) {
	s.TimeRange.start = start
	s.TimeRange.end = end
}

func SecretsQuery() *SecretsQueryOption {
	return &SecretsQueryOption{
		WhereEqCondition:   make(map[string]interface{}),
		WhereLikeCondition: make(map[string]string),
		WhereInCondition:   make(map[string]interface{}),
	}
}

func CountSecrets(ctx context.Context, rdb *gorm.DB, queryOptions *SecretsQueryOption) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 4*time.Second)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorSecret{})

		if len(queryOptions.WhereEqCondition) > 0 {
			db = db.Where(queryOptions.WhereEqCondition)
		}
		for k, v := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.WhereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		if !queryOptions.TimeRange.start.IsZero() {
			db = db.Where("created_at > ?", queryOptions.TimeRange.start)
		}
		if !queryOptions.TimeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.TimeRange.end)
		}
		db = db.Where("status=0")
		return db.Count(&cntNum).Error
	})

	return cntNum, err
}

func GetSecrets(ctx context.Context, rdb *gorm.DB, queryOptions *SecretsQueryOption, offset int, limit int) ([]*model.TensorSecret, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	var ingressRules []*model.TensorSecret
	notFound := false
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorSecret{})

		if len(queryOptions.WhereEqCondition) > 0 {
			db.Where(queryOptions.WhereEqCondition)
		}
		for k, v := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.WhereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		if !queryOptions.TimeRange.start.IsZero() {
			db = db.Where("created_at > ?", queryOptions.TimeRange.start)
		}
		if !queryOptions.TimeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.TimeRange.end)
		}

		db = db.Where("status=0")
		if offset >= 0 && limit >= 0 {
			db.Offset(offset).Limit(limit)
		}
		err := db.Order("id ASC").Find(&ingressRules).Error
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
	return ingressRules, nil
}

type PVQueryOption struct {
	WhereEqCondition   map[string]interface{}
	WhereLikeCondition map[string]string
	WhererInCondition  map[string]interface{}
	TimeRange          TimeRange
}

func (s *PVQueryOption) WithTimeRange(start, end time.Time) {
	s.TimeRange.start = start
	s.TimeRange.end = end
}

func PVQuery() *PVQueryOption {
	return &PVQueryOption{
		WhereEqCondition:   make(map[string]interface{}),
		WhereLikeCondition: make(map[string]string),
		WhererInCondition:  make(map[string]interface{}),
	}
}
func CountPVs(ctx context.Context, rdb *gorm.DB, queryOptions *PVQueryOption) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 4*time.Second)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorPV{})

		if len(queryOptions.WhereEqCondition) > 0 {
			db = db.Where(queryOptions.WhereEqCondition)
		}
		for k, v := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.WhererInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		if !queryOptions.TimeRange.start.IsZero() {
			db = db.Where("created_at > ?", queryOptions.TimeRange.start)
		}
		if !queryOptions.TimeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.TimeRange.end)
		}
		db = db.Where("status=0")
		return db.Count(&cntNum).Error
	})

	return cntNum, err
}

func GetPVs(ctx context.Context, rdb *gorm.DB, queryOptions *PVQueryOption, offset int, limit int) ([]*model.TensorPV, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	var pvs []*model.TensorPV
	notFound := false
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorPV{})

		if len(queryOptions.WhereEqCondition) > 0 {
			db.Where(queryOptions.WhereEqCondition)
		}
		for k, v := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.WhererInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		if !queryOptions.TimeRange.start.IsZero() {
			db = db.Where("created_at > ?", queryOptions.TimeRange.start)
		}
		if !queryOptions.TimeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.TimeRange.end)
		}

		db = db.Where("status=0")
		if offset >= 0 && limit >= 0 {
			db.Offset(offset).Limit(limit)
		}
		err := db.Order("id ASC").Find(&pvs).Error
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
	return pvs, nil
}

func UpsertSecrets(ctx context.Context, rdb *gorm.DB, secret *corev1.Secret, clusterKey string, updateTime time.Time) error {
	rCtx, cancel := context.WithTimeout(ctx, 5000*time.Millisecond)
	defer cancel()

	secr := newModeFromSecret(secret, clusterKey, updateTime)

	return rdb.WithContext(rCtx).Model(&model.TensorSecret{}).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(OnDupUpdatedColsForSecret),
	}).Create(secr).Error
}

func SoftDeleteSecret(ctx context.Context, rdb *gorm.DB, secret *corev1.Secret, clusterKey string, updateTime time.Time) error {
	tctx, cancel := context.WithTimeout(ctx, 3000*time.Millisecond)
	defer cancel()

	uuid := util.GenerateUUID(clusterKey, secret.Namespace, secret.Name)
	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(tctx, 1000*time.Millisecond)
		defer cancel()
		return rdb.WithContext(oneCtx).Model(&model.TensorSecret{}).Where("id = ?", uuid).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": updateTime,
		}).Error
	})
}

func newModeFromSecret(secret *corev1.Secret, clusterKey string, updateTime time.Time) *model.TensorSecret {
	return &model.TensorSecret{
		TableBase: model.TableBase{
			ID:        util.GenerateUUID(clusterKey, secret.Namespace, secret.Name),
			CreatedAt: secret.CreationTimestamp.Time,
			UpdatedAt: updateTime,
		},
		Name:       secret.Name,
		Namespace:  secret.Namespace,
		ClusterKey: clusterKey,
		UID:        string(secret.UID),
		Labels:     secret.Labels,
	}

}

func CleanUpUnUpdatedSecrets(ctx context.Context, rdb *gorm.DB, t time.Time, clusterKey string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
		defer cancel()

		return rdb.WithContext(oneCtx).Model(&model.TensorSecret{}).Where("updated_at < ? AND status = ? AND cluster_key = ?", t, 0, clusterKey).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": t,
		}).Error
	})
}

func UpsertPVs(ctx context.Context, rdb *gorm.DB, pv *corev1.PersistentVolume, clusterKey string, updateTime time.Time) error {
	rCtx, cancel := context.WithTimeout(ctx, 5000*time.Millisecond)
	defer cancel()

	tensorPV := newModelFromPV(pv, clusterKey, updateTime)

	return rdb.WithContext(rCtx).Model(&model.TensorPV{}).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(OnDupUpdatedColsForPV),
	}).Create(tensorPV).Error
}

func SoftDeletePV(ctx context.Context, rdb *gorm.DB, pv *corev1.PersistentVolume, clusterKey string, updateTime time.Time) error {
	tctx, cancel := context.WithTimeout(ctx, 3000*time.Millisecond)
	defer cancel()

	uuid := util.GenerateUUID(clusterKey, pv.Name)
	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(tctx, 1000*time.Millisecond)
		defer cancel()
		return rdb.WithContext(oneCtx).Model(&model.TensorPV{}).Where("id = ?", uuid).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": updateTime,
		}).Error
	})
}

func newModelFromPV(pv *corev1.PersistentVolume, clusterKey string, updateTime time.Time) *model.TensorPV {
	tensorPV := model.TensorPV{
		TableBase: model.TableBase{
			ID:        util.GenerateUUID(clusterKey, pv.Name),
			CreatedAt: pv.CreationTimestamp.Time,
			UpdatedAt: updateTime,
		},
		Name:                          pv.Name,
		ClusterKey:                    clusterKey,
		AccessMode:                    getShortAccessMode(string(pv.Spec.AccessModes[0])),
		StorageClassName:              pv.Spec.StorageClassName,
		Storage:                       pv.Spec.Capacity.Storage().String(),
		PvStatus:                      string(pv.Status.Phase),
		PersistentVolumeReclaimPolicy: string(pv.Spec.PersistentVolumeReclaimPolicy),
	}
	if pv.Spec.VolumeMode != nil {
		tensorPV.VolumeMode = string(*pv.Spec.VolumeMode)
	}
	if pv.Spec.ClaimRef != nil {
		tensorPV.ClaimRefName = pv.Spec.ClaimRef.Name
	}
	return &tensorPV
}
func getShortAccessMode(mode string) string {
	shortModeName := ""
	switch mode {
	case "ReadWriteOnce":
		shortModeName = "RWO"
	case "ReadOnlyMany":
		shortModeName = "ROX"
	case "ReadWriteMany":
		shortModeName = "RWX"
	case "ReadWriteOncePod":
		shortModeName = "RWOP"
	default:
		logging.GetLogger().Err(errors.New("invalid access_mode value,mode:" + mode))
		return ""
	}
	return shortModeName
}
func CleanUpUnUpdatedPVs(ctx context.Context, rdb *gorm.DB, t time.Time, clusterKey string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
		defer cancel()

		return rdb.WithContext(oneCtx).Model(&model.TensorPV{}).Where("updated_at < ? AND status = ? AND cluster_key = ?", t, 0, clusterKey).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": t,
		}).Error
	})
}

type PVCQueryOption struct {
	WhereEqCondition   map[string]interface{}
	WhereLikeCondition map[string]string
	WhereInCondition   map[string]interface{}
	TimeRange          TimeRange
}

func (s *PVCQueryOption) WithTimeRange(start, end time.Time) {
	s.TimeRange.start = start
	s.TimeRange.end = end
}

func PVCQuery() *PVCQueryOption {
	return &PVCQueryOption{
		WhereEqCondition:   make(map[string]interface{}),
		WhereLikeCondition: make(map[string]string),
		WhereInCondition:   make(map[string]interface{}),
	}
}
func CountPVCs(ctx context.Context, rdb *gorm.DB, queryOptions *PVCQueryOption) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 4*time.Second)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorPVC{})

		if len(queryOptions.WhereEqCondition) > 0 {
			db = db.Where(queryOptions.WhereEqCondition)
		}
		for k, v := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.WhereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		if !queryOptions.TimeRange.start.IsZero() {
			db = db.Where("created_at > ?", queryOptions.TimeRange.start)
		}
		if !queryOptions.TimeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.TimeRange.end)
		}
		db = db.Where("status=0")
		return db.Count(&cntNum).Error
	})

	return cntNum, err
}

func GetPVCs(ctx context.Context, rdb *gorm.DB, queryOptions *PVCQueryOption, offset int, limit int) ([]*model.TensorPVC, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	var pvs []*model.TensorPVC
	notFound := false
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorPVC{})

		if len(queryOptions.WhereEqCondition) > 0 {
			db.Where(queryOptions.WhereEqCondition)
		}
		for k, v := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.WhereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		if !queryOptions.TimeRange.start.IsZero() {
			db = db.Where("created_at > ?", queryOptions.TimeRange.start)
		}
		if !queryOptions.TimeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.TimeRange.end)
		}

		db = db.Where("status=0")
		if offset >= 0 && limit >= 0 {
			db.Offset(offset).Limit(limit)
		}
		err := db.Order("id ASC").Find(&pvs).Error
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
	return pvs, nil
}

func UpsertPVCs(ctx context.Context, rdb *gorm.DB, pvc *corev1.PersistentVolumeClaim, clusterKey string, updateTime time.Time) error {
	rCtx, cancel := context.WithTimeout(ctx, 5000*time.Millisecond)
	defer cancel()
	tensorPVC := newModelFromPVC(pvc, clusterKey, updateTime)

	return rdb.WithContext(rCtx).Model(&model.TensorPVC{}).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(OnDupUpdatedColsForPVC),
	}).Create(tensorPVC).Error
}

func SoftDeletePVC(ctx context.Context, rdb *gorm.DB, pvc *corev1.PersistentVolumeClaim, clusterKey string, updateTime time.Time) error {
	tctx, cancel := context.WithTimeout(ctx, 3000*time.Millisecond)
	defer cancel()

	uuid := util.GenerateUUID(clusterKey, pvc.Namespace, pvc.Name)
	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(tctx, 1000*time.Millisecond)
		defer cancel()
		return rdb.WithContext(oneCtx).Model(&model.TensorPVC{}).Where("id = ?", uuid).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": updateTime,
		}).Error
	})
}

func newModelFromPVC(pvc *corev1.PersistentVolumeClaim, clusterKey string, updateTime time.Time) *model.TensorPVC {
	tensorPVC := &model.TensorPVC{
		TableBase: model.TableBase{
			ID:        util.GenerateUUID(clusterKey, pvc.Namespace, pvc.Name),
			CreatedAt: pvc.CreationTimestamp.Time,
			UpdatedAt: updateTime,
		},
		Name:       pvc.Name,
		ClusterKey: clusterKey,
		Namespace:  pvc.Namespace,
		Storage:    pvc.Spec.Resources.Requests.Storage().String(),
		PVNames:    pvc.Spec.VolumeName,
		PvcStatus:  string(pvc.Status.Phase),
	}
	if len(pvc.Spec.AccessModes) != 0 {
		tensorPVC.AccessMode = getShortAccessMode(string(pvc.Spec.AccessModes[0]))
	}
	if pvc.Spec.StorageClassName != nil {
		tensorPVC.StorageClassName = *pvc.Spec.StorageClassName
	}
	if pvc.Spec.VolumeMode != nil {
		tensorPVC.VolumeMode = string(*pvc.Spec.VolumeMode)
	}
	if pvc.Spec.Resources.Limits.Storage() != nil && !pvc.Spec.Resources.Limits.Storage().IsZero() {
		tensorPVC.Storage += "~" + pvc.Spec.Resources.Limits.Storage().String()
	}
	return tensorPVC
}

func CleanUpUnUpdatedPVCs(ctx context.Context, rdb *gorm.DB, t time.Time, clusterKey string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
		defer cancel()

		return rdb.WithContext(oneCtx).Model(&model.TensorPVC{}).Where("updated_at < ? AND status = ? AND cluster_key = ?", t, 0, clusterKey).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": t,
		}).Error
	})
}

func CountNamespaceLabels(ctx context.Context, rdb *gorm.DB, queryOptions *NamespaceLabelQueryOption) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 4*time.Second)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorNamespaceLabel{})

		if len(queryOptions.WhereEqCondition) > 0 {
			db = db.Where(queryOptions.WhereEqCondition)
		}
		for k, v := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.WhereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		if !queryOptions.TimeRange.start.IsZero() {
			db = db.Where("created_at > ?", queryOptions.TimeRange.start)
		}
		if !queryOptions.TimeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.TimeRange.end)
		}
		db = db.Where("status=0")
		return db.Count(&cntNum).Error
	})

	return cntNum, err
}

func GetNamespaceLabels(ctx context.Context, rdb *gorm.DB, queryOptions *NamespaceLabelQueryOption, offset int, limit int) ([]*model.TensorNamespaceLabel, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	var pvs []*model.TensorNamespaceLabel
	notFound := false
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorNamespaceLabel{})

		if len(queryOptions.WhereEqCondition) > 0 {
			db.Where(queryOptions.WhereEqCondition)
		}
		for k, v := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.WhereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		if !queryOptions.TimeRange.start.IsZero() {
			db = db.Where("created_at > ?", queryOptions.TimeRange.start)
		}
		if !queryOptions.TimeRange.end.IsZero() {
			db = db.Where("created_at < ?", queryOptions.TimeRange.end)
		}

		db = db.Where("status=0")
		if offset >= 0 && limit >= 0 {
			db.Offset(offset).Limit(limit)
		}
		err := db.Order("id ASC").Find(&pvs).Error
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
	return pvs, nil
}

type PodBusiSvcBase struct {
	Id            uint32 `json:"id"`
	ContainerId   string `json:"containerId"`
	ContainerName string `json:"containerName"`
	SvcName       string `json:"svcName"`
	SvcVersion    string `json:"svcVersion"`
	SvcType       string `json:"svcType"`
	User          string `json:"user"`
	BinaryDir     string `json:"binaryDir"`
	ConfigDir     string `json:"configDir"`
}

type PodBusiSvcBaseDetail struct {
	model.TensorRawContainerSvc
	ClusterKey    string             `json:"clusterKey"`
	Namespace     string             `json:"namespace"`
	ContainerId   string             `json:"containerId"`
	ContainerName string             `json:"containerName"`
	PodName       string             `json:"podName"`
	Ports         model.PortSlice    `json:"ports"`
	Processes     model.ProcessSlice `json:"processes"`
}

func CountBusiSvcs(ctx context.Context, rdb *gorm.DB, queryOptions *BusiSvcQueryOption) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 4*time.Second)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorRawContainerSvc{})

		if len(queryOptions.WhereEqCondition) > 0 {
			db = db.Where(queryOptions.WhereEqCondition)
		}
		for k, v := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.WhereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		db = db.Where("ivan_assets_raw_containers_svcs.status=0")
		db = db.Joins("left join ivan_assets_raw_containers raw on  raw.id = ivan_assets_raw_containers_svcs.raw_container_id")
		db = db.Where("raw.status=0")
		if queryOptions.ContainerName != "" {
			db = db.Where("raw.name like ?", GetLikeExpr(queryOptions.ContainerName))
		}
		return db.Count(&cntNum).Error
	})
	return cntNum, err
}

func GetBusiSvcs(ctx context.Context, rdb *gorm.DB, queryOptions *BusiSvcQueryOption, offset int, limit int) ([]*PodBusiSvcBase, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	var svcs []*PodBusiSvcBase
	notFound := false
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorRawContainerSvc{}).
			Select("ivan_assets_raw_containers_svcs.*, raw.id as container_id ,raw.name as container_name")
		if len(queryOptions.WhereEqCondition) > 0 {
			db.Where(queryOptions.WhereEqCondition)
		}
		for k, v := range queryOptions.WhereLikeCondition {
			db = db.Where(fmt.Sprintf("%s LIKE ?", k), GetLikeExpr(v))
		}
		for k, v := range queryOptions.WhereInCondition {
			db = db.Where(fmt.Sprintf("%s IN ?", k), v)
		}
		db = db.Where("ivan_assets_raw_containers_svcs.status=0")
		db = db.Joins("left join ivan_assets_raw_containers raw on  raw.id = ivan_assets_raw_containers_svcs.raw_container_id")
		db = db.Where("raw.status=0")
		if queryOptions.ContainerName != "" {
			db = db.Where("raw.name like ?", GetLikeExpr(queryOptions.ContainerName))
		}
		if offset >= 0 && limit >= 0 {
			db.Offset(offset).Limit(limit)
		}
		err := db.Order("id ASC").Scan(&svcs).Error
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
	return svcs, nil
}

func GetBusiStartUser(ctx context.Context, rdb *gorm.DB, busiType string) ([]string, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	var users []string
	notFound := false
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorRawContainerSvc{}).
			Distinct("user")

		if busiType != "" {
			db = db.Where("svc_type = ? ", busiType)
		}
		db = db.Where("status=0 and user!=''")
		err := db.Scan(&users).Error
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
	return users, nil
}

func GetBusiSvcDetail(ctx context.Context, rdb *gorm.DB, id uint32) (*PodBusiSvcBaseDetail, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	detail := &PodBusiSvcBaseDetail{}
	notFound := false
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorRawContainerSvc{}).
			Select("ivan_assets_raw_containers_svcs.*,raw.cluster_key,raw.namespace, raw.id as container_id , raw.pod_name as pod_name ,raw.name as container_name,raw.processes,raw.ports").
			Where("ivan_assets_raw_containers_svcs.id=?", id)
		db = db.Joins("left join ivan_assets_raw_containers raw on  raw.id = ivan_assets_raw_containers_svcs.raw_container_id")
		err := db.Scan(detail).Error
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
	return detail, nil
}

type ExposeHostItem struct {
	Host     string
	Protocol string
	PathList []*ExposeHostPathBase
	Tags     []string
}

type ExposeHostPathBase struct {
	Id        uint32 `json:"id" gorm:"column:id;"`
	IngressId uint32 `json:"ingressId" gorm:"column:ingressId;"`
	Host      string `json:"host" gorm:"column:host;"`
	WebDesc   string `json:"WebDesc" gorm:"column:web_desc"`
	//HostIp         string `json:"hostIp"`
	Protocol       string `json:"protocol" gorm:"column:protocol;"`
	HostPort       string `json:"hostPort" gorm:"column:hostPort;"`
	ContainerPort  string `json:"containerPort" gorm:"column:containerPort;"`
	ContainerNames string `json:"containerNames" gorm:"column:containerNames;"`
	ContainerIds   string
	BackendKind    string `json:"backendKind" gorm:"column:backendKind;"`
	K8sSvcName     string `json:"k8sSvcName" gorm:"column:k8sSvcName;"`
	SvcName        string `json:"svcName,omitempty" gorm:"column:svcName;"`
	RootDir        string `json:"rootDir,omitempty" gorm:"column:rootDir;"`
	ClusterKey     string `json:"clusterKey" gorm:"column:clusterKey;"`
	Namespace      string `json:"namespace" gorm:"column:namespace;"`
}

func CountExposeHost(ctx context.Context, rdb *gorm.DB, webDesc string, protocols []string, hosts []string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	var cntNum int64
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 4*time.Second)
		defer oneCancel()

		var db *gorm.DB
		db = rdb.WithContext(oneCtx).Model(&model.TensorIngressRule{})
		if len(webDesc) > 0 {
			db = db.Where("host like ?", GetLikeExpr(webDesc))
		}
		if len(protocols) > 0 {
			db = db.Where("protocol in ?", protocols)
		}
		if len(hosts) > 0 {
			db = db.Where("host in ?", hosts)
		}
		db = db.Where("status =0 ").Distinct("host")
		return db.Count(&cntNum).Error
	})
	return cntNum, err
}

func GetExposeHosts(ctx context.Context, rdb *gorm.DB, webDesc string, protocols, hosts []string, offset, limit int) ([]*ExposeHostItem, error) {
	rCtx, cancel := context.WithTimeout(ctx, 10000*time.Millisecond)
	defer cancel()

	var db *gorm.DB
	var hostList []string
	db = rdb.WithContext(rCtx).Model(&model.TensorIngressRule{}).Distinct("host")
	if len(webDesc) > 0 {
		db = db.Where("host like ?", GetLikeExpr(webDesc))
	}
	if len(protocols) > 0 {
		db = db.Where("protocol in ?", protocols)
	}
	if len(hosts) > 0 {
		db = db.Where("host in ?", hosts)
	}
	if offset >= 0 && limit >= 0 {
		db.Offset(offset).Limit(limit)
	}
	err := db.Order("host ASC").Scan(&hostList).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if len(hostList) == 0 {
		return nil, err
	}
	var baseList []*ExposeHostPathBase
	db = rdb.WithContext(rCtx).Model(&model.TensorIngressRule{}).
		Select("ivan_assets_ingress_rules.id ,ingress_id as ingressId,cluster_key as clusterKey ,namespace,host,web_desc ," +
			"protocol,service_port as hostPort,backend_kind as backendKind ,backend_name as k8sSvcName")
	db = db.Joins("join ivan_assets_ingresses  ingress on ingress.id= ivan_assets_ingress_rules.ingress_id")
	db = db.Where("host in ?", hostList)
	db = db.Where("ingress.status =0 ")
	err = db.Order("host , path").Scan(&baseList).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(baseList) == 0 {
		return nil, nil
	}

	for _, base := range baseList {
		k8sService := &model.TensorService{}
		err := rdb.WithContext(rCtx).Model(&model.TensorService{}).Where("cluster_key = ? and namespace=? and name=? and status=0", base.ClusterKey, base.Namespace, base.K8sSvcName).Select("ports").
			Find(&k8sService).Error
		if err != nil {
			logging.GetLogger().Err(err).Msgf("select service failed.")
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			continue
		}
		// containerPort
		for _, port := range k8sService.Ports {
			if port.Port == base.HostPort {
				base.ContainerPort = port.TargetPort
				break
			}
		}
		if base.ContainerPort == "" {
			logging.GetLogger().Debug().Msgf("get ContainerPort failed.")
			continue
		}
		//	containerNames
		var podNames []string
		err = rdb.WithContext(rCtx).Model(&model.TensorEndpoints{}).Select("sub.name").Where("ivan_assets_endpoints.cluster_key = ? and ivan_assets_endpoints.namespace=? and ivan_assets_endpoints.name=? and ivan_assets_endpoints.status=0", base.ClusterKey, base.Namespace, base.K8sSvcName).
			Joins("join  ivan_assets_endpointsSubsets sub on sub.endpoints_id=ivan_assets_endpoints.id").Where("sub.status=0 and sub.target_ref_kind='Pod'").
			Scan(&podNames).Error
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get podNames failed.")
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			continue
		}
		matchStr := fmt.Sprintf(`"ContainerPort":%s,`, base.ContainerPort)
		type containerIdName struct {
			Id   string `json:"id"`
			Name string `json:"name"`
		}
		var containerIdNames []containerIdName
		err = rdb.WithContext(rCtx).Model(&model.TensorRawContainer{}).Select("id,name").
			Where("cluster_key = ? and namespace=? and pod_name in ? and status=0", base.ClusterKey, base.Namespace, podNames).
			Where("ports like ? ", GetLikeExpr(matchStr)).
			Scan(&containerIdNames).Error
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get containerNames failed.")
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			continue
		}
		var containerNames []string
		for _, idName := range containerIdNames {
			containerNames = append(containerNames, idName.Name)
		}
		if len(containerNames) == 0 {
			continue
		}
		base.ContainerNames = strings.Join(containerNames, " , ")
	}

	var result []*ExposeHostItem
	hostMap := make(map[string]struct{})
	for _, base := range baseList {
		if _, isOk := hostMap[base.Host]; isOk {
			result[len(result)-1].PathList = append(result[len(result)-1].PathList, base)
		} else {
			result = append(result, &ExposeHostItem{
				Host:     base.Host,
				Protocol: base.Protocol,
				PathList: []*ExposeHostPathBase{base},
			})
			hostMap[base.Host] = struct{}{}
		}
	}

	return result, nil
}

type ExposeHostDetail struct {
	*ExposeHostPathBase
	User  string          `json:"user"`
	Ports model.PortSlice `json:"ports"`
}

func GetExposeHostDetail(ctx context.Context, rdb *gorm.DB, id int64) (*ExposeHostDetail, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	detail := &ExposeHostDetail{}
	db := rdb.WithContext(rCtx).Model(&model.TensorIngressRule{}).
		Select("ivan_assets_ingress_rules.id ,ingress_id as ingressId,cluster_key as clusterKey ,namespace,web_desc as webDesc ," +
			"protocol,service_port as hostPort,backend_kind as backendKind ,backend_name as k8sSvcName")
	db = db.Joins("join ivan_assets_ingresses  ingress on ingress.id= ivan_assets_ingress_rules.ingress_id")
	err := db.Where("ivan_assets_ingress_rules.id=?", id).Scan(detail).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("select service failed.")
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, gorm.ErrRecordNotFound) {
			return detail, err
		}
	}

	k8sService := &model.TensorService{}
	err = rdb.WithContext(rCtx).Model(&model.TensorService{}).Where("cluster_key = ? and namespace=? and name=? and status=0", detail.ClusterKey, detail.Namespace, detail.K8sSvcName).Select("ports").
		Find(k8sService).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("select service failed.")
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, gorm.ErrRecordNotFound) {
			return detail, err
		}
	}
	// containerPort
	for _, port := range k8sService.Ports {
		if port.Port == detail.HostPort {
			detail.ContainerPort = port.TargetPort
			break
		}
	}
	if detail.ContainerPort == "" {
		logging.GetLogger().Debug().Msgf("get ContainerPort failed.")
		return detail, nil
	}
	//	containerNames
	var podNames []string
	err = rdb.WithContext(rCtx).Model(&model.TensorEndpoints{}).Select("sub.name").Where("ivan_assets_endpoints.cluster_key = ? and ivan_assets_endpoints.namespace=? and ivan_assets_endpoints.name=? and ivan_assets_endpoints.status=0", detail.ClusterKey, detail.Namespace, detail.K8sSvcName).
		Joins("join  ivan_assets_endpointsSubsets sub on sub.endpoints_id=ivan_assets_endpoints.id").Where("sub.status=0 and sub.target_ref_kind='Pod'").
		Scan(&podNames).Error
	if err != nil || len(podNames) == 0 {
		logging.GetLogger().Err(err).Msgf("get podNames failed.")
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, gorm.ErrRecordNotFound) {
			return detail, err
		}
		return detail, nil
	}
	matchStr := fmt.Sprintf(`"ContainerPort":%s,`, detail.ContainerPort)
	type containerIdName struct {
		Id    string          `json:"id"`
		Name  string          `json:"name"`
		Ports model.PortSlice `json:"ports" `
	}
	var containerIdNames []containerIdName
	err = rdb.WithContext(rCtx).Model(&model.TensorRawContainer{}).Select("id,name,ports").
		Where("cluster_key = ? and namespace=? and pod_name in ? and status=0", detail.ClusterKey, detail.Namespace, podNames).
		Where("ports like ? ", GetLikeExpr(matchStr)).
		Scan(&containerIdNames).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get containerNames failed.")
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, gorm.ErrRecordNotFound) {
			return detail, nil
		}
		return detail, nil
	}
	var containerNames []string
	var containerIds []string
	var ports model.PortSlice
	for _, idName := range containerIdNames {
		containerNames = append(containerNames, idName.Name)
		containerIds = append(containerIds, idName.Id)
		ports = append(ports, idName.Ports...)
	}
	if len(containerNames) == 0 {
		return detail, nil
	}
	detail.ContainerNames = strings.Join(containerNames, ",")
	detail.ContainerIds = strings.Join(containerIds, ",")
	detail.Ports = ports
	//busiSvc
	type busiTemp struct {
		SvcName string `json:"svcName"`
		RootDir string `json:"rootDir"`
		User    string `json:"user"`
	}
	var busiSvc busiTemp
	err = rdb.WithContext(rCtx).Model(&model.TensorRawContainerSvc{}).Select("svc_name,root_dir,user").
		Where("pod_name = ? and port =? ", podNames[0], detail.ContainerPort).
		Scan(&busiSvc).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get busiSvc failed.")
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, gorm.ErrRecordNotFound) {
			return detail, err
		}
		return detail, nil
	}
	detail.SvcName = busiSvc.SvcName
	detail.RootDir = busiSvc.RootDir
	detail.User = busiSvc.User

	return detail, nil
}

func DeleteRawContainerWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, clusterKey, id string, stopTime time.Time) error {
	rCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	return rdb.WithContext(rCtx).Transaction(func(tx *gorm.DB) error {
		err := deleteRawContainerWithTx(tx, clusterKey, id, stopTime)

		if err != nil {
			return err
		}
		err = deleteResourceImageByRawContainer(rCtx, redisClient, []uint32{util.GenerateUUID(id)})
		if err != nil {
			return err
		}
		return redisClient.DeleteDoc(rCtx, fmt.Sprintf("rawContainer:%s", id))
	})
}

func DeleteRawContainer(ctx context.Context, rdb *gorm.DB, clusterKey, id string, stopTime time.Time) error {
	rCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	return rdb.WithContext(rCtx).Transaction(func(tx *gorm.DB) error {
		return deleteRawContainerWithTx(tx, clusterKey, id, stopTime)
	})

}

func deleteRawContainerWithTx(tx *gorm.DB, clusterKey, id string, stopTime time.Time) error {
	err := tx.Model(&model.TensorRawContainer{}).Where("cluster_key = ? and id = ?", clusterKey, id).Updates(map[string]interface{}{
		"status":         assets.Exited,
		"last_stop_time": stopTime,
		"updated_at":     time.Now(),
	}).Error
	if err != nil {
		return err
	}
	err = tx.Where("raw_container_id=?", id).Delete(&model.TensorRawContainerSvc{}).Error
	if err != nil {
		return err
	}
	return tx.Where("raw_container_id=?", id).Delete(&model.TensorRawContainerFramework{}).Error
}

func DeleteRawContainerSyncReason(ctx context.Context, rdb *gorm.DB, clusterKey, namespace, id string) error {
	rCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	query := model.TensorResource{}
	db := rdb.Model(&model.TensorResource{}).WithContext(rCtx)
	db = db.Where("cluster_key = ? and namespace = ? and reason like ?", clusterKey, namespace, "%"+id+"%")
	err := db.First(&query).Error
	if err != nil {
		return err
	}
	var reasonList []model.ReasonItem
	err = json.Unmarshal([]byte(query.Reason), &reasonList)
	if err != nil {
		return err
	}
	var runningList []model.ReasonItem
	for _, v := range reasonList {
		if v.ID != id {
			continue
		}
		runningList = append(runningList, v)
	}
	reasonBytes, err := json.Marshal(runningList)
	if err != nil {
		return err
	}

	tmpData := model.TensorResource{Reason: string(reasonBytes[:])}
	tmpData.IsSupportDrift = true
	for _, v := range runningList {
		tmpData.IsSupportDrift = tmpData.IsSupportDrift && v.IsSupportDrift
		if !tmpData.IsSupportDrift {
			break
		}
	}
	err = db.Select("reason", "is_support_drift").Updates(&tmpData).Error
	return err
}

func CleanUpRawContainerWithRedis(ctx context.Context, rdb *gorm.DB, redisClient *redisearch.Client, ts time.Time, clusterKey, nodeName string) error {
	rCtx, cancel := context.WithTimeout(ctx, 5000*time.Millisecond)
	defer cancel()

	rawQuery := fmt.Sprintf("@cluster_key:{%s} @node_name:{%s} @updated_at:[-inf (%d]", redisearch.EscapeTextFileString(clusterKey), redisearch.EscapeTextFileString(nodeName), ts.UnixMilli())

	return util.RetryWithBackoff(rCtx, func() error {

		oneCtx, oneCacel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCacel()

		_, total, err := redisClient.Search(oneCtx, redisearch.NewQuery(rawQuery).Limit(0, 0))
		if err != nil {
			return err
		}

		result, _, err := redisClient.Search(oneCtx, redisearch.NewQuery(rawQuery).Limit(0, total).SetReturnFields("id"))
		if err != nil {
			return err
		}

		keys := make([]string, 0, len(result))
		containerUuid := make([]uint32, 0, len(result))
		for _, doc := range result {
			keys = append(keys, cast.ToString(doc.Id))
			containerUuid = append(containerUuid, util.GenerateUUID(doc.Id))
		}

		err = rdb.WithContext(oneCtx).Transaction(func(tx *gorm.DB) error {
			dbErr := tx.Model(&model.TensorRawContainer{}).
				Where("cluster_key = ? and node_name = ? and updated_at < ? and status <5 ", clusterKey, nodeName, ts).Updates(map[string]interface{}{
				"status":     assets.Exited,
				"updated_at": time.Now(),
			}).Error
			if dbErr != nil {
				return dbErr
			}
			if len(keys) == 0 {
				return nil
			}
			logging.GetLogger().Info().Msgf("本次容器清理，clean count:%d", len(keys))
			// clean svc,framework
			err = rdb.Where(" updated_at < ? and  raw_container_id in ?", ts, keys).Delete(&model.TensorRawContainerSvc{}).Error
			if err != nil {
				return err
			}
			err = rdb.Where(" updated_at < ? and raw_container_id in ?", ts, keys).Delete(&model.TensorRawContainerFramework{}).Error
			if err != nil {
				return err
			}
			logging.GetLogger().Info().Msgf("CleanUpRawContainer delete Zset:container_images  nodeName:%s from redis: %v", nodeName, containerUuid)
			err := deleteResourceImageByRawContainer(rCtx, redisClient, containerUuid)
			if err != nil {
				return err
			}
			logging.GetLogger().Info().Msgf("CleanUpRawContainer delete raw container nodeName:%s from redis: %v", nodeName, keys)
			return redisClient.DeleteDoc(oneCtx, keys...)
		})
		return err
	})
}

// clean up from redis
func CleanUpRawContainer(ctx context.Context, rdb *gorm.DB, ts time.Time, clusterKey, nodeName string) error {
	rCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	return rdb.WithContext(rCtx).Transaction(func(tx *gorm.DB) error {
		var rawIds []string
		err := rdb.Model(&model.TensorRawContainer{}).Where("cluster_key = ? and node_name = ? and updated_at < ? and status < 5", clusterKey, nodeName, ts).Pluck("id", &rawIds).Error
		if err != nil {
			return err
		}
		logging.GetLogger().Info().Msgf("clean inactive container count:%d", len(rawIds))
		if len(rawIds) == 0 {
			return nil
		}
		err = rdb.Model(&model.TensorRawContainer{}).Where("id in ?", rawIds).Updates(map[string]interface{}{
			"status":     assets.Exited,
			"updated_at": time.Now(),
		}).Error
		if err != nil {
			return err
		}
		err = rdb.Where(" updated_at < ? and  raw_container_id in ?", ts, rawIds).Delete(&model.TensorRawContainerSvc{}).Error
		if err != nil {
			return err
		}
		return rdb.Where(" updated_at < ? and  raw_container_id in ?", ts, rawIds).Delete(&model.TensorRawContainerFramework{}).Error
	})
}

func DeleteClusterAll(ctx context.Context, rdb *gorm.DB, clusterKey string) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	return rdb.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.WithContext(ctx).Where("cluster_key = ?", clusterKey).Delete(&model.TensorResource{}).Error
		if err != nil {
			return err
		}
		err = tx.WithContext(ctx).Where("cluster_key = ?", clusterKey).Delete(&model.TensorContainer{}).Error
		if err != nil {
			return err
		}

		err = tx.Where("cluster_key = ?", clusterKey).Delete(&model.TensorContainerRelation{}).Error
		if err != nil {
			return err
		}

		var ids []uint32
		err = tx.Model(&model.TensorRawContainerFramework{}).Select("ivan_assets_raw_containers_frameworks.id").
			Joins("join ivan_assets_raw_containers on ivan_assets_raw_containers.id =  ivan_assets_raw_containers_frameworks.raw_container_id").
			Where("ivan_assets_raw_containers.cluster_key = ?", clusterKey).Scan(&ids).Error
		if err != nil {
			return err
		}
		if len(ids) > 0 {
			err = tx.Table(model.TensorRawContainerFramework{}.TableName()).
				Where("in  = ?", ids).Delete(&model.TensorRawContainerFramework{}).Error
			if err != nil {
				return err
			}
		}

		err = tx.Table(model.TensorRawContainerSvc{}.TableName()).Select("ivan_assets_raw_containers_svcs.id").
			Joins("join ivan_assets_raw_containers on ivan_assets_raw_containers.id =  ivan_assets_raw_containers_svcs.raw_container_id").
			Where("ivan_assets_raw_containers.cluster_key = ?", clusterKey).Scan(&ids).Error
		if err != nil {
			return err
		}
		if len(ids) > 0 {
			err = tx.Table(model.TensorRawContainerSvc{}.TableName()).
				Where("in  = ?", ids).Delete(&model.TensorRawContainerSvc{}).Error
			if err != nil {
				return err
			}
		}

		err = tx.Where("cluster_key = ?", clusterKey).Delete(&model.TensorRawContainer{}).Error
		if err != nil {
			return err
		}

		err = tx.WithContext(ctx).Where("cluster_key = ?", clusterKey).Delete(&model.TensorNamespace{}).Error
		if err != nil {
			return err
		}

		err = tx.WithContext(ctx).Where("cluster_key = ?", clusterKey).Delete(&model.TensorService{}).Error
		if err != nil {
			return err
		}

		var endpointsIdList []uint32
		endpoints := &model.TensorEndpoints{}
		err = tx.WithContext(ctx).Table(endpoints.TableName()).Where("cluster_key = ?", clusterKey).Pluck("id", &endpointsIdList).Error
		if err != nil {
			return err
		}
		if len(endpointsIdList) > 0 {
			err = tx.WithContext(ctx).Where("id in ?", endpointsIdList).Delete(endpoints).Error
			if err != nil {
				return err
			}
			err = tx.WithContext(ctx).Where("endpoints_id in ?", endpointsIdList).Delete(&model.TensorEndpointsSubset{}).Error
			if err != nil {
				return err
			}
		}

		var ingressIds []uint32
		ingress := &model.TensorIngress{}
		err = tx.WithContext(ctx).Table(ingress.TableName()).Where("cluster_key = ?", clusterKey).Pluck("id", &ingressIds).Error
		if err != nil {
			return err
		}
		if len(ingressIds) > 0 {
			err = tx.WithContext(ctx).Where("id in ?", ingressIds).Delete(ingress).Error
			if err != nil {
				return err
			}
			err = tx.WithContext(ctx).Where("ingress_id in ?", ingressIds).Delete(&model.TensorIngressRule{}).Error
			if err != nil {
				return err
			}
		}

		err = tx.WithContext(ctx).Where("cluster_key = ?", clusterKey).Delete(&model.TensorSecret{}).Error
		if err != nil {
			return err
		}

		err = tx.WithContext(ctx).Where("cluster_key = ?", clusterKey).Delete(&model.TensorPV{}).Error
		if err != nil {
			return err
		}

		err = tx.WithContext(ctx).Where("cluster_key = ?", clusterKey).Delete(&model.TensorPVC{}).Error
		if err != nil {
			return err
		}

		err = tx.WithContext(ctx).Where("cluster_key = ?", clusterKey).Delete(&model.TensorNamespaceLabel{}).Error
		if err != nil {
			return err
		}

		err = tx.WithContext(ctx).Where("cluster_key = ?", clusterKey).Delete(&model.BaitService{}).Error
		if err != nil {
			return err
		}
		err = tx.WithContext(ctx).Where("id = ?", clusterKey).Delete(&model.TensorCluster{}).Error
		if err != nil {
			return err
		}
		return nil
	})
}

func GetRuleVersions(ctx context.Context, rdb *gorm.DB, offset int, limit int) ([]string, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	var clusters []*model.TensorCluster
	notFound := false
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()

		err := rdb.WithContext(oneCtx).Distinct("rule_version").Find(&clusters).Error
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
	var ruleVersions []string
	for _, c := range clusters {
		ruleVersions = append(ruleVersions, c.RuleVersion)
	}
	return ruleVersions, nil
}

func CountRuleVersions(ctx context.Context, rdb *gorm.DB) (int64, error) {
	rCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	defer cancel()

	var count int64
	err := util.RetryWithBackoff(rCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(rCtx, 2000*time.Millisecond)
		defer oneCancel()
		err := rdb.WithContext(oneCtx).Model(&model.TensorCluster{}).Distinct("rule_version").Count(&count).Error
		return err
	})
	return count, err
}

type AppQueryOption struct {
	whereEqCondition      map[string]interface{}
	whereNotNullCondition map[string]struct{}
	whereLikeCondition    map[string]string
}

func AppQuery() *AppQueryOption {
	return &AppQueryOption{
		whereEqCondition:      make(map[string]interface{}, 3),
		whereNotNullCondition: make(map[string]struct{}, 2),
		whereLikeCondition:    make(map[string]string),
	}
}

func (q *AppQueryOption) WithAppType(appType string) *AppQueryOption {
	q.whereEqCondition["app_type"] = appType
	return q
}

func (q *AppQueryOption) WithApaTargetName(targetName string) *AppQueryOption {
	q.whereEqCondition["app_target_name"] = targetName
	return q
}

func (q *AppQueryOption) WithAppTargetVer(version string) *AppQueryOption {
	q.whereEqCondition["app_target_version"] = version
	return q
}

func (q *AppQueryOption) WithCluster(cluster_key string) *AppQueryOption {
	q.whereEqCondition["cluster_key"] = cluster_key
	return q
}

func (q *AppQueryOption) WithFuzzyResourceName(resName string) *AppQueryOption {
	q.whereLikeCondition["resource_name"] = resName
	return q
}

func GetResourceApp(ctx context.Context, rdb *gorm.DB, query *AppQueryOption, offset, limit int) (apps []*model.ResourceApp, err error) {
	pgCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	err = util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.ResourceApp{}).Where("status = ?", 0)
		// Distinct("cluster_key", "namespace", "resource_name", "app_target_name", "app_target_version")
		if len(query.whereEqCondition) > 0 {
			db = db.Where(query.whereEqCondition)
		}
		if len(query.whereLikeCondition) > 0 {
			for column, val := range query.whereLikeCondition {
				db = db.Where(fmt.Sprintf("%s LIKE ?", column), GetLikeExpr(val))
			}
		}
		if limit > 0 && offset >= 0 {
			db = db.Offset(offset).Limit(limit)
		}
		return db.Find(&apps).Error
	})
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func CountResourceApp(ctx context.Context, rdb *gorm.DB, query *AppQueryOption) (int64, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	var count int64
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
		defer cancel()

		db := rdb.WithContext(oneCtx).Model(&model.ResourceApp{}).Where("status = ?", 0)
		// Distinct("cluster_key", "namespace", "resource_name", "app_target_name", "app_target_version")
		if len(query.whereEqCondition) > 0 {
			db = db.Where(query.whereEqCondition)
		}
		if len(query.whereLikeCondition) > 0 {
			for column, val := range query.whereLikeCondition {
				db = db.Where(fmt.Sprintf("%s LIKE ?", column), GetLikeExpr(val))
			}
		}
		return db.Count(&count).Error
	})
	if err != nil {
		return count, err
	}
	return count, nil
}
