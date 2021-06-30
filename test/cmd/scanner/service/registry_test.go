package service

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	configPath string = "./config.yaml"
	// configPath string = "/configs/scanner/config.yaml"
)

type TestExtender struct {
	Name string
}

func (te *TestExtender) OutPut() {
	fmt.Println("hello world", te.Name)
}

func TestSyncRepo(t *testing.T) {
	t.Log("start sync repo")
	postgresDB, err := gorm.Open(postgres.Open("postgres://postgres:xxxxxx@192.168.134.26:5432/postgres?sslmode=disable"), &gorm.Config{})
	scannerDB := store.NewScannerDB(postgresDB)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	syncInterval := uint(5)
	r, err := service.NewSyncRepoImageByConfig(configPath, syncInterval)
	if err != nil {
		t.Fatalf("new sync repo image err:%v", err)
	}
	// fmt.Printf("数组长度为:%v", len(r))
	// fmt.Printf("ID为：%v %v", r[0], r[1])
	var wg sync.WaitGroup
	for i := range r {
		// fmt.Printf("Index :%v,v:%p", i, &r[i])
		wg.Add(1)
		tmp := r[i]
		go tmp.Run(func(image registry.Image) error {
			TransImagelist := component.TransImageToImagelist(tmp, image)
			scannerDB.InsertImageList(TransImagelist)
			return nil
		}, &wg)
	}
	r.MockRun(func(image registry.Image) error {
		te.OutPut()
		fmt.Println("image", image.ImageDigest)
		return nil
	})

	t.Log("end")
}
