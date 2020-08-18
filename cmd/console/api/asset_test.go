// +build !ci

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo"
)

/***
func TestFilterAssets(t *testing.T) {
	jsonFile, err := os.Open("../../../testdata/asset_cluster.json")
	if err != nil {
		fmt.Println(err)
	}

	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var clusters assetsClusters
	err = json.Unmarshal(byteValue, &clusters)
	if err != nil {
		fmt.Println(err)
	}

	newList := filterList(clusters.Assets, func(v assetOverviewItem) bool {
		return v.Type == "NODE"
	})

	fmt.Println(newList)

	assert.Assert(t, len(newList) != 0)
}
**/

func TestAssetsClusters(t *testing.T) {
	api, _, mongoTeardown := setupAPI(t, nil, false, true)
	defer func() {
		mongoTeardown()
	}()
	//init mongodb
	initClustersMongoDb(api.mongodb)
	initImagesMongoDb(api.mongodb)
	initContainersMongoDb(api.mongodb)

	//Do GET /assets/clusters
	req, _ := http.NewRequest(http.MethodGet, "", nil)
	w := httptest.NewRecorder()
	api.clusterAssets().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	body, _ := ioutil.ReadAll(w.Body)
	type respCluster struct {
		Items clusterList    `json:"list"`
		Page  paginationData `json:"pagination"`
	}
	var respc respCluster
	err := json.Unmarshal(body, &respc)
	assert.NoError(t, err)
	assert.Equal(t, 8, len(respc.Items))

	//Do GET /assets/images
	api.imageAssets().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	body, _ = ioutil.ReadAll(w.Body)
	type respImage struct {
		Items imageList      `json:"list"`
		Page  paginationData `json:"pagination"`
	}
	var respi respImage
	err = json.Unmarshal(body, &respi)
	assert.NoError(t, err)
	assert.Equal(t, 6, len(respi.Items))

	//Do GET /assets/containers
	api.dockerAssets().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	body, _ = ioutil.ReadAll(w.Body)
	type respContainer struct {
		Items containerList  `json:"list"`
		Page  paginationData `json:"pagination"`
	}
	var respcon respContainer
	err = json.Unmarshal(body, &respcon)
	assert.NoError(t, err)
	assert.Equal(t, 7, len(respcon.Items))

}

func initImagesMongoDb(mdb *mongo.Database) {
	data := []imageOverviewItem{}
	for i := 0; i < 6; i++ {
		data = append(data, imageOverviewItem{
			fmt.Sprintf("%d", i), fmt.Sprintf("nginx:1.1.%d", i),
			"nginx", fmt.Sprintf("1.1.%d", i), "管理员", "镜像描述",
			rand.Intn(100), rand.Intn(2), time.Now(),
			time.Now(),
			fmt.Sprintf(
				"sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0%d%d00", i, i),
			[]vulnerabilityOverviewItem{
				{"0", rand.Intn(10)},
				{"1", rand.Intn(8)},
				{"2", rand.Intn(15)},
			},
		})
	}
	aif := make([]interface{}, len(data))

	for i, v := range data {
		aif[i] = v
	}

	collection := mdb.Collection(imageAssetCol)
	insertManyResult, err := collection.InsertMany(context.TODO(), aif)
	if err != nil {
		log.Fatal()
	}
	fmt.Println("Init Images")
	fmt.Println("Inserted multiple documents: ", insertManyResult.InsertedIDs)
}

func initContainersMongoDb(mdb *mongo.Database) {
	type resp struct {
		Items containerList  `json:"list"`
		Page  paginationData `json:"pagination"`
	}
	items := []asssetsContainerOverviewItem{
		{
			"10", "容器1", "容器1-1", "管理员", rand.Intn(10), "nginx:latest", 1,
			123, rand.Intn(3), time.Now(), time.Now(),
		},
		{
			"20", "容器2", "容器1-2", "管理员", rand.Intn(10), "nginx:latest", 1,
			124, rand.Intn(3), time.Now(), time.Now(),
		},
		{
			"30", "容器3", "容器1-3", "管理员", rand.Intn(10), "nginx:latest", 1,
			125, rand.Intn(3), time.Now(), time.Now(),
		},
		{
			"40", "容器4", "容器1-4", "管理员", rand.Intn(10), "nginx:latest", 1,
			126, rand.Intn(3), time.Now(), time.Now(),
		},
		{
			"50", "容器5", "容器1-5", "管理员", rand.Intn(10), "nginx:latest", 1,
			127, rand.Intn(3), time.Now(), time.Now(),
		},
		{
			"06", "容器6", "容器1-6", "管理员", rand.Intn(10), "nginx:latest", 1,
			128, rand.Intn(3), time.Now(), time.Now(),
		},
		{
			"07", "容器7", "容器1-7", "管理员", rand.Intn(10), "nginx:latest", 1,
			129, rand.Intn(3), time.Now(), time.Now(),
		},
	}

	aif := make([]interface{}, len(items))

	for i, v := range items {
		aif[i] = v
	}

	collection := mdb.Collection(containerAssetCol)
	insertManyResult, err := collection.InsertMany(context.TODO(), aif)
	if err != nil {
		log.Fatal()
	}
	fmt.Println("Init Container")
	fmt.Println("Inserted multiple documents: ", insertManyResult.InsertedIDs)
}
func initClustersMongoDb(mdb *mongo.Database) {
	assets := getTestData()
	aif := make([]interface{}, len(assets))

	for i, v := range assets {
		aif[i] = v
	}

	collection := mdb.Collection(clusterAssetCol)
	insertManyResult, err := collection.InsertMany(context.TODO(), aif)
	if err != nil {
		log.Fatal()
	}
	fmt.Println("Init client")
	fmt.Println("Inserted multiple documents: ", insertManyResult.InsertedIDs)
}

func getTestData() []clusterOverviewItem {
	jsonFile, err := os.Open("../../../testdata/asset_cluster.json")
	if err != nil {
		fmt.Println(err)
	}

	byteValue, _ := ioutil.ReadAll(jsonFile)
	m := make(map[string]interface{})
	err = json.Unmarshal(byteValue, &m)
	if err != nil {
		fmt.Println(err)
	}

	data, err := json.Marshal(m["list"])
	if err != nil {
		fmt.Println(err)
	}
	var assets []clusterOverviewItem
	err = json.Unmarshal(data, &assets)
	if err != nil {
		fmt.Println(err)
	}
	return assets
}
