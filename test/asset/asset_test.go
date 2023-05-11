package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	rsearch "github.com/March-deng/godisearch/redisearch"
	"github.com/spf13/cast"
	"github.com/stretchr/testify/assert"
	passets "gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/console/api"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	ppassets "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/redisearch"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

func setupDB() *gorm.DB {

	db, err := gorm.Open(mysql.Open(os.Getenv("ASSET_TEST_MYSQL_URL")))
	panicOnError(err)

	db.AutoMigrate(&model.TensorContainer{})

	return db
}

func setupRedis() *redisearch.Client {
	// os.Setenv("REDIS_CLUSTER_URL", "localhost:6379")
	// os.Setenv("REDIS_PASSWORD", "123456")

	client, err := redisearch.NewClient()
	panicOnError(err)

	for _, index := range passets.AssetIndices {
		err = client.CreateIndex(context.Background(), index)
		panicOnError(err)
	}

	return client
}

// func teardown(db *gorm.DB, client *redisearch.Client) error {
// 	return nil
// }

func loadResource() []*model.TensorResource {
	path := os.Getenv("ASSET_RESOURCE_JSON_FILE")
	data, err := os.ReadFile(path)
	panicOnError(err)

	resources := make([]*model.TensorResource, 0)

	err = json.Unmarshal(data, &resources)
	panicOnError(err)
	return resources
}

func TestUpsertResourceWithRedis(t *testing.T) {
	db := setupDB()
	client := setupRedis()

	c, err := client.GetIndexClient("resource")
	panicOnError(err)
	resources := loadResource()

	for _, resource := range resources {
		_, err := dal.UpsertResourceWithRedis(context.Background(), db, c, modelResource2TensorResource(resource), time.Now())

		panicOnError(err)

		fmt.Println("successfully set ", resource.ID)
	}

}

type resourceQueryOption struct {
	clusterKey string
	name       string
	kind       string
	namespace  string
}

func (r *resourceQueryOption) ToResourceQueryOption() *dal.ResourcesQueryOption {
	opt := dal.ResourcesQuery()

	if r.clusterKey != "" {
		opt.WithCluster(r.clusterKey)
	}

	if r.kind != "" {
		opt.WithResourceKind(ppassets.ResourceKind(r.kind))
	}

	if r.name != "" {
		opt.WithFuzzyName(r.name)
	}
	if r.namespace != "" {
		opt.WithFuzzyNamespace(r.namespace)
	}

	return opt
}

func TestGetResoucesWithRedis(t *testing.T) {
	db := setupDB()
	client := setupRedis()
	c, err := client.GetIndexClient("resource")
	panicOnError(err)

	type queryOpt struct {
		name      string
		condition *resourceQueryOption
	}

	var queryOpts = []*queryOpt{
		{
			name:      "集群与命名空间搜索",
			condition: &resourceQueryOption{kind: "Pod", namespace: "boss-ha-yx-billing", clusterKey: "7c3ab3e9-eb63-4920-b27e-53da91ab3980"},
		},
		{
			name:      "名称搜索",
			condition: &resourceQueryOption{kind: "Pod", name: "bill-rate-sum-ggprs"},
		},
	}

	for _, opt := range queryOpts {
		t.Run(opt.name, func(t *testing.T) {
			dbCount, err := dal.CountResources(context.Background(), db, opt.condition.ToResourceQueryOption())
			assert.Nil(t, err)

			redisCount, err := dal.CountResourcesWithRedis(context.Background(), db, c, opt.condition.ToResourceQueryOption())
			assert.Nil(t, err)

			if !assert.Equal(t, dbCount, redisCount) {
				t.Fatalf("condition %s failed, got %d resource from db, but got %d resource redis", opt.name, dbCount, redisCount)
			}

			// 每一次查询十条记录
			round := dbCount%10 + 1

			for i := 0; i < int(round); i++ {
				dbRes, err := dal.GetResources(context.Background(), db, opt.condition.ToResourceQueryOption(), i*10, 10)
				assert.Nil(t, err)

				redisRes, err := dal.GetResourcesWithRedis(context.Background(), db, c, opt.condition.ToResourceQueryOption(), i*10, 10)
				assert.Nil(t, err)

				// 比对查出的数据id

				dbIDs := make(map[uint32]struct{})
				redisIDs := make(map[uint32]struct{})

				for _, r := range dbRes {
					dbIDs[r.ID] = struct{}{}
				}
				for _, r := range redisRes {
					redisIDs[r.ID] = struct{}{}
				}

				assert.Equal(t, dbIDs, redisIDs)
			}
		})

	}
}

func TestCountResourceWithRedis(t *testing.T) {
	db := setupDB()
	client := setupRedis()
	c, err := client.GetIndexClient("resource")
	panicOnError(err)

	type queryOpt struct {
		condition *resourceQueryOption
	}

	var queryOpts = []*queryOpt{
		{
			condition: &resourceQueryOption{kind: "Pod", namespace: "boss-ha-yx-billing", clusterKey: "7c3ab3e9-eb63-4920-b27e-53da91ab3980"},
		},
		{
			condition: &resourceQueryOption{kind: "Pod", name: "bill-rate-sum-ggprs"},
		},
	}

	for _, opt := range queryOpts {
		dbCount, err := dal.CountResources(context.Background(), db, opt.condition.ToResourceQueryOption())
		assert.Nil(t, err)

		redisCount, err := dal.CountResourcesWithRedis(context.Background(), db, c, opt.condition.ToResourceQueryOption())
		assert.Nil(t, err)

		assert.Equal(t, dbCount, redisCount)
	}
}

func TestDeleteResourceWithResource(t *testing.T) {
	db := setupDB()
	client := setupRedis()
	c, err := client.GetIndexClient("resource")
	panicOnError(err)

	resources := []*ppassets.TensorResource{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "rat-freeres-transfer-10-228-100-146-320166-9-1th", Namespace: "boss-ha-yx-billing"},
			Kind:       ppassets.ResourceKind("Pod"),
			Cluster:    "7c3ab3e9-eb63-4920-b27e-53da91ab3980",
		},
	}

	for _, r := range resources {
		rID := dal.GetResourceUUID(r.Cluster, r.Namespace, string(r.Kind), r.Name)
		fmt.Println(rID)
		err = dal.SoftDeleteResourceWithRedis(context.Background(), db, c, r, time.Now())
		assert.Nil(t, err)

		res, err := dal.GetResources(context.Background(), db, dal.ResourcesQuery().WithID(rID), 0, 1)
		assert.Nil(t, err)

		assert.Empty(t, res)

		_, err = c.GetDoc(context.Background(), fmt.Sprintf("resource:%d", rID))
		assert.Equal(t, err, rsearch.ErrDocNotFound)
	}

}

func TestCleanUpUnUpdatedResourcesWithRedis(t *testing.T) {
	db := setupDB()
	client := setupRedis()
	c, err := client.GetIndexClient("resource")
	panicOnError(err)

	until := time.Unix(1682235991, 0)
	cluster := "4f4c7596-9284-4163-bd21-34b10481e092"
	err = dal.CleanUpUnUpdatedResourcesWithRedis(context.Background(), db, c, until, cluster)
	assert.Nil(t, err)

	rawQuery := fmt.Sprintf("@cluster_key:{%s} @updated_at:[-inf (%d]", rsearch.EscapeTextFileString(cluster), 1682235991)

	query := rsearch.NewQuery(rawQuery).SetReturnFields("id").Limit(0, 0)

	_, total, err := c.Search(context.Background(), query)
	assert.Nil(t, err)
	assert.Empty(t, total)

}

func modelResource2TensorResource(m *model.TensorResource) *ppassets.TensorResource {
	r := &ppassets.TensorResource{}
	r.Name = m.Name
	r.Namespace = m.Namespace
	r.Cluster = m.ClusterKey
	r.UID = types.UID(m.UID)
	r.Kind = ppassets.ResourceKind(m.Kind)

	if m.LabelSelector != nil {
		r.LabelSelector = &metav1.LabelSelector{
			MatchLabels:      m.LabelSelector.MatchLabels,
			MatchExpressions: m.LabelSelector.MatchExpressions,
		}
	}

	if len(m.OwnerReferences) > 0 {
		r.OwnerReferences = make([]metav1.OwnerReference, len(m.OwnerReferences))
		for i, ref := range m.OwnerReferences {
			r.OwnerReferences[i].Kind = ref.Kind
			r.OwnerReferences[i].Name = ref.Kind
		}
	}

	if len(m.Labels) != 0 {
		labels := make(map[string]string)
		err := json.Unmarshal(m.Labels, &labels)
		panicOnError(err)
		r.Labels = labels
	}

	if m.PodTemplate != nil {
		r.PodTemplate = &corev1.PodTemplateSpec{}
		r.PodTemplate.Spec.InitContainers = m.PodTemplate.InitContainers
		r.PodTemplate.Spec.Containers = m.PodTemplate.Containers
		r.PodTemplate.Spec.ServiceAccountName = m.PodTemplate.ServiceAccountName
		r.PodTemplate.Spec.NodeName = m.PodTemplate.NodeName
		r.PodTemplate.Spec.HostNetwork = m.PodTemplate.HostNetwork
		r.PodTemplate.Spec.HostPID = m.PodTemplate.HostPID
		r.PodTemplate.Spec.HostIPC = m.PodTemplate.HostIPC
		r.PodTemplate.Spec.SecurityContext = m.PodTemplate.PodSecurityContext
	}

	r.CreateTime = m.CreatedAt

	return r
}

func setupRDBClient() *databases.RDBInstance {
	opt := databases.Options{
		RdbUser:         "ivan",
		RdbHost:         "192.168.3.20",
		RdbPassword:     "Mysql-ha@123",
		RdbPort:         30036,
		RdbDbname:       "ivan",
		RdbReadonlyHost: "192.168.3.20",
	}

	c, err := databases.NewRDBClient(&opt)

	panicOnError(err)
	return c
}

func TestResourceFuzzyOnLocal02(t *testing.T) {
	db := setupRDBClient()
	rClient := setupRedis()

	assets.InitResourcesService(db, rClient, "")

	var requests = []*api.GetResourceFuzzy{

		{
			Limit:  10,
			Offset: 0,
			Kind:   "Deployment",
		},

		{
			Limit:  10,
			Offset: 10,
			Kind:   "Deployment",
		},
		{
			Limit:     10,
			Offset:    0,
			Kind:      "Deployment",
			Namespace: "tensor",
			Name:      "tensor",
		},

		{
			Limit:      10,
			Offset:     0,
			Namespace:  "tensor",
			Name:       "tensor",
			ClusterKey: "f815c6f8-8264-46a0-a273-c039de27492d",
		},

		{
			Limit:      10,
			Offset:     10,
			Namespace:  "tensor",
			Name:       "tensor",
			ClusterKey: "f815c6f8-8264-46a0-a273-c039de27492d",
		},
	}

	for _, req := range requests {
		tCtx, _ := context.WithTimeout(context.Background(), 10*time.Second)

		req.UseRedis = true

		redisResources, redisTotal, err := req.Execute(tCtx)
		assert.Nil(t, err)
		req.UseRedis = false
		dbResources, dbTotal, err := req.Execute(tCtx)
		assert.Nil(t, err)

		assert.Equal(t, dbTotal, redisTotal)

		assert.Equal(t, len(dbResources), len(redisResources))

		redisIDs := make([]uint32, 0)
		for _, r := range redisResources {
			redisIDs = append(redisIDs, r.ID)
		}
		dbIDs := make([]uint32, 0)
		for _, r := range dbResources {
			dbIDs = append(dbIDs, r.ID)
		}

		fmt.Printf("From DB:    %v \n", dbIDs)
		fmt.Printf("From Redis: %v \n", redisIDs)
		assert.Equal(t, dbIDs, redisIDs)
	}

}

func TestPodFuzzyOnLocal02(t *testing.T) {
	db := setupRDBClient()
	rClient := setupRedis()

	err := assets.InitResourcesService(db, rClient, "")
	panicOnError(err)

	var requests = []*api.GetPods{
		{
			Limit:      10,
			Offset:     0,
			ClusterKey: "f815c6f8-8264-46a0-a273-c039de27492d",
			Namespace:  "tensorsec",
		},
		{
			Limit:      10,
			Offset:     10,
			ClusterKey: "f815c6f8-8264-46a0-a273-c039de27492d",
			Namespace:  "tensorsec",
		},
		{
			Limit:      10,
			Offset:     0,
			ClusterKey: "f815c6f8-8264-46a0-a273-c039de27492d",
			Namespace:  "tensorsec",
			Name:       "tensor",
		},
		{
			Limit:      10,
			Offset:     0,
			ClusterKey: "f815c6f8-8264-46a0-a273-c039de27492d",
			Namespace:  "tensorsec",
			Name:       "master",
		},
	}

	for _, req := range requests {
		tCtx, _ := context.WithTimeout(context.Background(), 10*time.Second)

		req.UseRedis = true

		redisResources, redisTotal, err := req.Execute(tCtx)
		assert.Nil(t, err)
		req.UseRedis = false
		dbResources, dbTotal, err := req.Execute(tCtx)
		assert.Nil(t, err)

		assert.Equal(t, dbTotal, redisTotal)

		assert.Equal(t, len(dbResources), len(redisResources))

		redisIDs := make([]uint32, 0)
		for _, r := range redisResources {
			redisIDs = append(redisIDs, r.ID)
		}
		dbIDs := make([]uint32, 0)
		for _, r := range dbResources {
			dbIDs = append(dbIDs, r.ID)
		}

		fmt.Printf("From DB:    %v \n", dbIDs)
		fmt.Printf("From Redis: %v \n", redisIDs)
		assert.Equal(t, dbIDs, redisIDs)
	}

}

func TestRawContainerFuzzyOnLocal02(t *testing.T) {
	db := setupRDBClient()
	rClient := setupRedis()

	err := assets.InitResourcesService(db, rClient, "")
	panicOnError(err)

	var k8sManaged bool = true

	var requests = []*api.GetRawContainers{
		{
			Limit:      10,
			Offset:     0,
			ClusterKey: "f815c6f8-8264-46a0-a273-c039de27492d",
			K8sManaged: &k8sManaged,
		},
		{
			Limit:      10,
			Offset:     0,
			ClusterKey: "f815c6f8-8264-46a0-a273-c039de27492d",
			K8sManaged: &k8sManaged,
			Status:     []int{0, 1, 2, 3, 4},
		},
		{
			Limit:      10,
			Offset:     0,
			ClusterKey: "f815c6f8-8264-46a0-a273-c039de27492d",
			K8sManaged: &k8sManaged,
			Status:     []int{0, 1, 2, 3, 4},
			NodeNames:  []string{"node"},
		},
		{
			Limit:      10,
			Offset:     0,
			ClusterKey: "f815c6f8-8264-46a0-a273-c039de27492d",
			K8sManaged: &k8sManaged,
			Status:     []int{0, 1, 2, 3, 4},
			NodeNames:  []string{"node"},
			Namespaces: []string{"tensor"},
		},
		{
			Limit:      10,
			Offset:     0,
			ClusterKey: "f815c6f8-8264-46a0-a273-c039de27492d",
			K8sManaged: &k8sManaged,
			Status:     []int{0, 1, 2, 3, 4},
			NodeNames:  []string{"cluster02"},
		},
		{
			Limit:      10,
			Offset:     10,
			ClusterKey: "f815c6f8-8264-46a0-a273-c039de27492d",
			K8sManaged: &k8sManaged,
			Status:     []int{0, 1, 2, 3, 4},
			NodeNames:  []string{"cluster02"},
		},
	}

	for _, req := range requests {
		tCtx, _ := context.WithTimeout(context.Background(), 10*time.Second)

		req.UseRedis = true

		redisResources, redisTotal, err := req.Execute(tCtx)
		assert.Nil(t, err)
		req.UseRedis = false
		dbResources, dbTotal, err := req.Execute(tCtx)
		assert.Nil(t, err)

		assert.Equal(t, dbTotal, redisTotal)

		assert.Equal(t, len(dbResources), len(redisResources))

		redisIDs := make([]string, 0)
		for _, r := range redisResources {
			redisIDs = append(redisIDs, r.ContainerID)
		}
		dbIDs := make([]string, 0)
		for _, r := range dbResources {
			dbIDs = append(dbIDs, r.ContainerID)
		}

		fmt.Printf("From DB:    %v \n", dbIDs)
		fmt.Printf("From Redis: %v \n", redisIDs)
		assert.Equal(t, dbIDs, redisIDs)
	}

}

func TestAllRawContainer(t *testing.T) {
	db := setupRDBClient()
	rClient := setupRedis()

	err := assets.InitResourcesService(db, rClient, "")
	panicOnError(err)

	dbContainer := make([]*model.TensorRawContainer, 0)

	dbSet := make(map[string]struct{})

	err = db.Get().Model(&model.TensorRawContainer{}).Where("status <5 ").Find(&dbContainer).Error
	if err != nil {
		panic(err)
	}

	for _, container := range dbContainer {
		dbSet[container.ContainerID] = struct{}{}
	}

	ic, err := rClient.GetIndexClient("rawContainer")
	panicOnError(err)

	// raw := fmt.Sprintf("@node_name:{cluster02*}")

	docs, total, err := ic.Search(context.Background(), rsearch.NewQuery("@node_name:{cluster02*}").Limit(0, 10000))
	panicOnError(err)

	redisSet := make(map[string]struct{})

	for _, doc := range docs {
		redisSet[cast.ToString(doc.Properties["id"])] = struct{}{}
	}

	fmt.Println(len(dbContainer), total)

	fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	fmt.Println("presented in redis, but not in db")

	{

		for id := range redisSet {
			_, ok := dbSet[id]
			if !ok {
				fmt.Println(id)
			}
		}
	}
	fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	fmt.Println("presented in db, but not in redis")
	{
		for id := range dbSet {
			_, ok := redisSet[id]
			if !ok {
				fmt.Println(id)
			}
		}
	}

}

func TestCleanUpRawContainerWithRedis(t *testing.T) {
	// db := setupRDBClient()
	rClient := setupRedis()

	ic, err := rClient.GetIndexClient("rawContainer")
	panicOnError(err)

	_, count, err := ic.Search(context.Background(), rsearch.NewQuery(`@k8s_managed:{true} @status:{Running|Created|Restarted|Moving|Paused} @node_name:{*node*}`).Limit(0, 0))
	panicOnError(err)
	fmt.Println(count)
}

func TestDiffRawContainer(t *testing.T) {
	db := setupRDBClient()
	rClient := setupRedis()

	ic, err := rClient.GetIndexClient("rawContainer")
	panicOnError(err)

	docs, _, err := ic.Search(context.Background(), rsearch.NewQuery("@k8s_managed:{true}").Limit(0, 1000))
	panicOnError(err)

	for _, doc := range docs {
		id := cast.ToString(doc.Properties["id"])
		status := cast.ToString(doc.Properties["status"])

		c := &model.TensorRawContainer{}
		err = db.Get().Model(c).Where("id = ? ", id).Find(c).Error
		if err != nil {
			fmt.Println(c.ContainerID)
			continue
		}

		if ppassets.GetRawContainerStatus(int(c.Status)) != status {
			fmt.Println(c.ContainerID, ppassets.GetRawContainerStatus(int(c.Status)), status, c.Status)
		}
	}

	containers := make([]*model.TensorRawContainer, 0)

	err = db.Get().Model(&model.TensorRawContainer{}).Where("status < ?", 5).Find(&containers).Error
	panicOnError(err)

	for _, c := range containers {

		_, err := ic.GetDoc(context.Background(), fmt.Sprintf("rawContainer:%s", c.ContainerID))
		if err != nil {
			fmt.Println(c.ContainerID, c.UpdatedAt)
		}

	}

}

func TestSyncToRedis(t *testing.T) {
	db := setupDB()
	rClient := setupRedis()

	ic, err := rClient.GetIndexClient("resource")
	panicOnError(err)

	var (
		minID    uint32
		cursor   uint32
		total    int64
		finished int64
	)

	m := &model.TensorResource{}

	// 首选查询出总数
	err = db.Model(m).Where("status = ? ", 0).Count(&total).Error
	panicOnError(err)

	resources := make([]*model.TensorResource, 0)

	// 查询最小的id
	err = db.Model(m).Where("status = ?", 0).Order("id asc").Limit(1).Find(&resources).Error
	panicOnError(err)

	if len(resources) == 0 {
		panic("no resources found")
	}

	minID = resources[0].ID

	ctx := context.Background()
	cursor = minID - 1

	for finished < total {
		resources = resources[:0]

		err = db.Model(m).Where("status = ? ", 0).Where("id between (?, ?)", cursor, cursor+1000).Find(&resources).Error
		panicOnError(err)

		var curCount int64

		for _, resource := range resources {
			doc := rsearch.NewDocument(fmt.Sprintf("resource:%d", resource.ID), 1).
				Set("id", resource.ID).
				Set("name", resource.Name).
				Set("namespace", resource.Namespace).
				Set("cluster_key", resource.ClusterKey).
				Set("kind", resource.Kind).
				Set("updated_at", resource.UpdatedAt.UnixMilli())

			err = ic.AddDoc(ctx, doc)
			if err != nil {
				panic(fmt.Sprintf("err occured when insert to %d resource to redis, err: %v", resource.ID, err))
			}

			curCount++
		}
		finished += curCount

		fmt.Printf("finished: %d, total: %d, %d/%d, percentage: %.2f \n", finished, total, finished, total, float64(finished)/float64(total))
	}

}

func TestPodFuzzyQuery(t *testing.T) {
	db := setupRDBClient()
	rClient := setupRedis()

	err := assets.InitResourcesService(db, rClient, "")
	panicOnError(err)

	var request = &api.GetPods{
		ClusterKey:   "f815c6f8-8264-46a0-a273-c039de27492d",
		ResourceName: "kube",
		PodIP:        "135",
		Limit:        10,
		Offset:       0,
		UseRedis:     true,
	}

	_, total, err := request.Execute(context.Background())
	panicOnError(err)
	fmt.Println(total)
}
