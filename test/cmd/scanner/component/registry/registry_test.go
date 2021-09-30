package registry

import (
	"fmt"
	"testing"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/hwswr"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type TestExtender struct {
	Name string
}

func (te *TestExtender) OutPut() {
	fmt.Println("hello world", te.Name)
}

const (
	swrUrl       = "https://swr.cn-north-4.myhuaweicloud.com"
	swrUser      = "cn-north-4@MYNJS5KQGERCFK1MYEWX"
	swrPassword  = "748ba613dcb18a8af6b16426daf0e614adde55404f370cb6e2ee62292740fbb7"
	swrAccessKey = "MYNJS5KQGERCFK1MYEWX"
	swrSecretKey = "ELHiGSl0Del8pbJmg8XRKP6W3U7ng0362KuU8NB7"
	swrRegion    = "cn-north-4"
)

func dumpImages(images []registry.Image) {
	for _, v := range images {
		tmpImage := &registry.Image{}
		tmpImage.Repository = v.Repository
		tmpImage.Tag = v.Tag
		tmpImage.ImageDigest = v.ImageDigest
		logging.GetLogger().Info().Msgf("image:%+v", *tmpImage)
	}
}

func TestListImages(t *testing.T) {
	t.Log("start test list images")
	driver, err := registry.Open(registry.RegistrableComponentConfig{
		Type: hwswr.Version,
		Options: map[string]interface{}{
			"url": swrUrl,
			// "password":      swrPassword,
			// "username":      swrUser,
			"skiptlsverify": true,
			"accesskey":     swrAccessKey,
			"secretkey":     swrSecretKey,
			// "region":        swrRegion,
		},
	})
	if err != nil {
		t.Fatalf("open driver err:%v", err)
	}
	images, err := driver.ListImages(func(image registry.Image) error {
		return nil
	}, true)
	if err != nil {
		t.Fatalf("list images err:%v", images)
	}
	dumpImages(images)
	t.Logf("end")
}
