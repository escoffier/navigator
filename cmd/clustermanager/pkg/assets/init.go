package assets

import (
	"errors"
	"os"
	"runtime/debug"
	"sync"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/kubemonitor"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/microseg"
	pkgassets "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
)

var (
	initOnce sync.Once
	//wInstance *assets.Watcher
	wInstance *pkgassets.Watcher
)

// Watcher singleton
func Watcher(rdb *databases.RDBInstance,
	redisCli *redis.Client,
	scannerURL string,
	reader mq.Reader,
	topic, groupID string,
) (*pkgassets.Watcher, error) {
	if rdb == nil || redisCli == nil || scannerURL == "" {
		return nil, errors.New("illegal argument")
	}
	initOnce.Do(func() {
		logging.Get().Info().Msgf("Init assets.Watcher: stack = %s", debug.Stack())
		wInstance = pkgassets.NewWatcher(reader, topic, groupID)
		wInstance.AddCallback(newPodResourcesService(redisCli, rdb))
		wInstance.AddCallback(microseg.NewResourcesListener(rdb))
		kbm, err := kubemonitor.NewService()
		if err == nil {
			wInstance.AddCallback(kbm.RiskMonitor())
		} else {
			logging.Get().Err(err).Msg("init kube monitor error")
		}
		wInstance.AddCallback(newResourcesWatcher(rdb, scannerURL))
		wInstance.AddCallback(newHoneyspotService(rdb))

		exportContainers := os.Getenv("EXPORT_CONTAINERS")
		if exportContainers == "true" {
			wInstance.AddCallback(newPodContainerWatcher(rdb))
		}
	})
	return wInstance, nil
}
