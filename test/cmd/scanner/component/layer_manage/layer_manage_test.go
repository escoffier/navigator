package layer_manage

import (
	"context"
	"github.com/heroku/docker-registry-client/registry"
	layerManage "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/layer_manage"
	"sync"
	"testing"
	"time"
)

func ClientPullLayer(t *testing.T, llms *layerManage.LocalLayerManageSrv, num int) {
	t.Logf("client %d started", num)

	url := "http://192.168.208.79:80"
	username := "admin"
	password := "Harbor12345"
	repository := "test/test"
	//digest := "sha256:56c7bee8935f8f6f75ca64ca37bb01e70b2bc7fd1792ba1da9ba7b748c629223"
	digest := "sha256:c67f3896b22c1378881cbbb9c9d1edfe881fd07f713371835ef46d93c649684d"
	client, err := layerManage.NewLocalLayerManageClient(llms)

	defer func() {
		//delete layer
		err = client.DeleteLayer(digest)
		if err != nil {
			t.Fatalf("delete layer err %v", err)
		}
		t.Logf("client %d delete layer ok.digest %s", num, digest)
	}()

	if err != nil {
		t.Fatalf("client %d new local layer manage client err %v", num, err)
	}

	layerUrl, httpUrl, err := client.GetLayer(username, password, url, repository, digest, true)
	if err != nil {
		t.Fatalf("get layer err %v", err)
	}
	t.Logf("client %d get layer url %s,httpurl %s", num, layerUrl, httpUrl)
}

func TestLayerManageServer(t *testing.T) {
	t.Log("start test")

	//start server
	externalIp := "192.168.208.79"
	serverIp := "192.168.208.79"
	mainCtx, _ := context.WithCancel(context.Background())
	llms, err := layerManage.NewLocalLayerManageSrv(mainCtx, serverIp, 5566, 6677, externalIp)
	if err != nil {
		t.Fatalf("create server err %v", err)
	}

	t.Log("starting server")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := llms.Run()
		if err != nil {
			t.Fatalf("local layer manage run err %v", err)
		}
	}()

	time.Sleep(time.Duration(2) * time.Second)

	//
	var wg1 sync.WaitGroup
	t.Log("starting client")
	for i := 0; i < 4; i++ {
		wg1.Add(1)
		go func(i int) {
			defer wg1.Done()
			ClientPullLayer(t, llms, i)
		}(i)
	}
	wg1.Wait()

	time.Sleep(time.Duration(20) * time.Second)
	wg.Wait()
}

func RegistryClientPull(t *testing.T, num int) {
	url := "https://quay.io/"
	username := "wadeling"
	password := "!quay0723!"
	hub, err := registry.New(url, username, password)
	if err != nil {
		t.Logf("num %d first err,retry", num)

		//retry
		var hub1 *registry.Registry
		for i := 0; i < 5; i++ {
			time.Sleep(time.Duration(2) * time.Second)
			hub1, err = registry.New(url, username, password)
			if err != nil {
				t.Fatalf("num %d create client err %v", num, err)
				return
			}
			t.Logf("num %d retry ok", num)
			break
		}

		hub = hub1
	}

	repositories, err := hub.Repositories()
	if err != nil {
		t.Fatalf("get repo err %v", err)
		return
	}
	//t.Logf("get repo %v",repositories)

	if len(repositories) == 0 {
		t.Log("empty repo")
		return
	}
	//get tag
	repoName := repositories[0]
	tags, err := hub.Tags(repoName)
	if err != nil {
		t.Fatalf("get tags err %v", err)
		return
	}
	if len(tags) == 0 {
		t.Fatalf("repo %s not found tag", repoName)
		return
	}
	t.Logf("num %d get tag %v", num, tags)

	//get manifest digest
	md, err := hub.ManifestDigest(repoName, "nginx")
	t.Logf("md %s", md.String())
	return
	//get manitest
	tagName := tags[0]
	manifest, err := hub.ManifestV2(repoName, tagName)
	if err != nil {
		t.Fatalf("get manifest err %v", err)
		return
	}
	if len(manifest.Manifest.Layers) == 0 {
		t.Fatalf("repo %s,tag %s ,not found layer", repoName, tagName)
		return
	}

	//get  layer
	digest := manifest.Manifest.Layers[0].Digest
	reader, err := hub.DownloadBlob(repoName, digest)
	if reader != nil {
		defer reader.Close()
	}
	if err != nil {
		t.Fatalf("download layer err.digest %s", digest)
		return
	}
}

func TestRegistryClient(t *testing.T) {
	//multi time request test
	//for i:=0;i<10;i++ {
	//	RegistryClientPull(t)
	//}
	//t.Log("multi time req end")

	//concurrent test
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			RegistryClientPull(t, i)
		}(i)
	}
	t.Log("concurrent test end")
	wg.Wait()
}
