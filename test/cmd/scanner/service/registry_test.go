package service

import (
	"fmt"
	"testing"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service"
)

var (
	//configPath string = "./config.yaml"
	configPath string = "./config-registryv2.yaml"
)

type TestExtender struct {
	Name string
}

func (te *TestExtender) OutPut() {
	fmt.Println("hello world", te.Name)
}

func TestSyncRepo(t *testing.T) {
	t.Log("start sync repo")

	syncInterval := uint(5)
	r, err := service.NewSyncRepoImageByConfig(configPath, syncInterval)
	if err != nil {
		t.Fatalf("new sync repo image err:%v", err)
	}

	te := &TestExtender{
		Name: "annie",
	}
	r.MockRun(func(image registry.Image) error {
		te.OutPut()
		fmt.Println("image", image.ImageDigest)
		return nil
	})

	t.Log("end")
}
