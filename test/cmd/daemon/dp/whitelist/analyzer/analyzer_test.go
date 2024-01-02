package analyzer

import (
	"os"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist/analyzer"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist/analyzer/all"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/global"
)

var (
	testImage = "wade23/deploy:deploytest"
)

func prepare() error {
	// for local test,set socket
	err := os.Setenv("DOCKER_SOCKET_ADDR", "unix:///var/run/docker.sock")
	if err != nil {
		return err
	}
	err = os.Setenv("DAEMON_RUN_MODE", global.DaemonRunModeLocal)
	if err != nil {
		return err
	}
	logging.Get().SetLevel(zerolog.TraceLevel)
	return nil
}

func TestDeviceMapper(t *testing.T) {
	t.Log("start")
	if err := prepare(); err != nil {
		t.Fatalf("prepare err:%v", err)
	}

	runtimeCli, err := dp.CreateRuntimeCli("docker")
	if err != nil {
		t.Fatalf("failed to create runtime cli.%v", err)
	}

	image, err := runtimeCli.GetImageInspect("default", testImage)
	if err != nil {
		t.Fatalf("failed to inspect image.%v", err)
	}

	ifErr := false
	num := 1
	wg := sync.WaitGroup{}
	for i := 0; i < num; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wl, err2 := analyzer.Analyze(runtimeCli, image)
			if err2 != nil {
				ifErr = true
				t.Errorf("failed to analyze whitelist.%v", err2)
				return
			}
			t.Logf("whitelist len:%v", len(wl))
			_ = analyzer.DumpExecFileList("test-whitelist.txt", wl)

			assert.NotEqual(t, len(wl), 0)
		}()
	}
	wg.Wait()

	if ifErr {
		t.Fatalf("failed.")
	}
	t.Log("end")
}
