package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/docker/distribution/manifest/schema2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/go-containerregistry/pkg/name"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	layerManage "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/layer_manage"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnnvd"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnvd"
	"gitlab.com/piccolo_su/vegeta/pkg/redistools"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/trivy"
)

var (
	llms        *layerManage.LocalLayerManageSrv
	trivyServer *component.TrivyServer
)

func DeleteLayerFromLLms(layers []string) {
	client, _ := layerManage.NewLocalLayerManageClient(llms)
	for i := range layers {
		client.DeleteLayer(layers[i])
	}
}

func GetLayerFromLLMS(library string, repositoryName string, tag string) []string {
	client1, _ := layerManage.NewLocalLayerManageClientT(llms, "/manifest")
	client, _ := layerManage.NewLocalLayerManageClient(llms)
	if library != "index.docker.io" {
		library = "http://" + library
	} else {
		library = "https://" + library
	}
	manifestTmp, _ := client1.GetManifest("admin", "Harbor12345", library, repositoryName, tag, true)
	uniqueLayers := make(map[string]bool)
	layers := make([]string, 0)
	manifest := schema2.DeserializedManifest{}
	manifest.UnmarshalJSON([]byte(manifestTmp))
	fmt.Println(manifestTmp)
	layers = append(layers, manifest.Config.Digest.String())
	for _, layer := range manifest.Manifest.Layers {
		layerDigest := layer.Digest.String()
		if _, ok := uniqueLayers[layerDigest]; ok {
			// return []string{}, fmt.Errorf("Found duplicate layer digest in V2 manifest")
			continue
		}
		uniqueLayers[layerDigest] = true
		layers = append(layers, layerDigest)
	}
	for layer := range layers {
		client.GetLayer("admin", "Harbor12345", library, repositoryName, layers[layer], true)
	}
	return layers
}

func taskDoing(c *gin.Context) {
	image := c.Query("image")
	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)

	ref, err := name.ParseReference(image, nameOpts...)
	repo := ref.Context()

	registryStr := repo.RegistryStr()

	tag := ref.Identifier()
	repositoryName := ref.Context().RepositoryStr()
	layers := GetLayerFromLLMS(registryStr, repositoryName, tag)
	Newimage := "0.0.0.0:5566/" + repositoryName + ":" + tag
	fmt.Println(Newimage)
	r, err := trivyServer.Scan(c, Newimage)
	DeleteLayerFromLLms(layers)
	if err != nil {
		c.String(200, err.Error())
		return
	}
	c.JSON(200, r)
}
func main() {
	os.Setenv("TRIVY_NON_SSL", "true")
	redisaddr := "192.168.134.26:26379,192.168.134.26:26379,192.168.134.26:26379"
	sa := strings.Split(redisaddr, ",")
	redisClient, err := redistools.NewTensorRedisClient(&redis.FailoverOptions{ // share data use db 0
		MasterName:    "mymaster",
		SentinelAddrs: sa,
		Password:      "123456",
		DB:            0,
	})
	if err != nil {
		panic(err)
	}
	trivyServer, err = component.NewTrivyServer(*redisClient, "/root/testdb/")
	if err != nil {
		panic(err)
	}
	trivyServer.Run(context.Background())

	router := gin.Default()
	router.GET("/trivy", taskDoing)
	go router.Run(":7777")
	llms, _ = layerManage.NewLocalLayerManageSrv(context.Background(), "0.0.0.0", 5566, 9278, "0.0.0.0")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		err := llms.Run()
		if err != nil {
			fmt.Println(err)
		}
	}()
	wg.Wait()
}
