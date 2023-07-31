package devicemapper

import (
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist/analyzer/devicemapper"
	"os"
	"testing"
)

var (
	testImageName = "wade23/deploy:deploytest"
)

func prepare() error {
	err := os.Setenv("DOCKER_SOCKET_ADDR", "unix:///var/run/docker.sock")
	return err
}

func TestChainId(t *testing.T) {
	if err := prepare(); err != nil {
		t.Fatalf("prepare err:%v", err)
	}

	runtime, err := dp.CreateRuntimeCli("docker")
	if err != nil {
		t.Fatalf("create runtime err:%v", err)
	}
	image, err := runtime.GetImageInspect("default", testImageName)
	if err != nil {
		t.Fatalf("inspect image failed")
	}

	diffIds := devicemapper.ApiTypeToRootFS(image.RootFS)
	chainId := devicemapper.CreateChainID(diffIds)
	t.Logf("chainid:%s", chainId.String())
}
