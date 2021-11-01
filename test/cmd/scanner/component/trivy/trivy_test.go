package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnnvd"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnvd"
	"gitlab.com/piccolo_su/vegeta/pkg/redistools"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/trivy"
)

func TestTrivy(t *testing.T) {

	redisaddr := "192.168.134.26:26379,192.168.134.26:26379,192.168.134.26:26379"
	sa := strings.Split(redisaddr, ",")
	redisClient, err := redistools.NewTensorRedisClient(&redis.FailoverOptions{ // share data use db 0
		MasterName:    "mymaster",
		SentinelAddrs: sa,
		Password:      "123456",
		DB:            0,
	})
	if err != nil {
		t.Fatal(err)
	}
	trivyServer, err = component.NewTrivyServer(*redisClient, "/root/testdb/")
	if err != nil {
		t.Fatal(err)
	}
	trivyServer.Run(context.Background())
	res, err := trivyServer.Scan(context.Background(), "192.168.134.26:80/fff/problem:latest")
	fmt.Println(err)
	fmt.Println(res)
	// router := gin.Default()
	// router.GET("/trivy", taskDoing)
	// go router.Run(":8080")
	// llms, _ = layerManage.NewLocalLayerManageSrv(context.Background(), "0.0.0.0", 5566, 9278, "0.0.0.0")
	// var wg sync.WaitGroup
	// wg.Add(1)
	// go func() {
	// 	err := llms.Run()
	// 	if err != nil {
	// 		fmt.Println(err)
	// 	}
	// }()
	// wg.Wait()

	// client1, _ := layerManage.NewLocalLayerManageClientT(llms, "/manifest")
	// client, _ := layerManage.NewLocalLayerManageClient(llms)
	// manifestTmp, _ := client1.GetManifest("admin", "Harbor12345", "http://192.168.134.26:80/", "fff/alltest", "latest", true)
	// uniqueLayers := make(map[string]bool)
	// layers := make([]string, 0)
	// manifest := schema2.DeserializedManifest{}
	// manifest.UnmarshalJSON([]byte(manifestTmp))
	// fmt.Println(manifestTmp)
	// layers = append(layers, manifest.Config.Digest.String())
	// for _, layer := range manifest.Manifest.Layers {
	// 	layerDigest := layer.Digest.String()
	// 	if _, ok := uniqueLayers[layerDigest]; ok {
	// 		// return []string{}, fmt.Errorf("Found duplicate layer digest in V2 manifest")
	// 		continue
	// 	}
	// 	uniqueLayers[layerDigest] = true
	// 	layers = append(layers, layerDigest)
	// }
	// for layer := range layers {
	// 	client.GetLayer("admin", "Harbor12345", "http://192.168.134.26:80", "fff/alltest", layers[layer], true)
	// }
	// wg.Wait()
}
