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
	"gitlab.com/security-rd/go-pkg/redisearch"
)

var (
	initOnce sync.Once
	//wInstance *assets.Watcher
	wInstance *pkgassets.Watcher

	disableKubeMonitor = false
)

func init() {
	disableFlag := os.Getenv("DISABLE_KUBE_MONITOR")
	if disableFlag == "1" {
		disableKubeMonitor = true
	}
}

// Watcher singleton
func Watcher(rdb *databases.RDBInstance,
	redisCli *redis.Client,
	searchClient *redisearch.Client,
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
		wInstance.AddCallback(newPodResourcesService(redisCli, rdb, searchClient))
		wInstance.AddCallback(microseg.NewResourcesListener(rdb))
		if !disableKubeMonitor {
			kbm, err := kubemonitor.NewService()
			if err == nil {
				wInstance.AddCallback(kbm.RiskMonitor())
			} else {
				logging.Get().Err(err).Msg("init kube monitor error")
			}
		} else {
			logging.Get().Warn().Msg("Kube Monitor is disabled according to the enviroment var")
		}

		wInstance.AddCallback(newResourcesWatcher(rdb, scannerURL, searchClient))
		wInstance.AddCallback(newHoneyspotService(rdb))
		wInstance.AddCallback(newRawContainerWatcher(rdb, searchClient))

		exportContainers := os.Getenv("EXPORT_CONTAINERS")
		if exportContainers == "true" {
			wInstance.AddCallback(newPodContainerWatcher(rdb))
		}
	})
	return wInstance, nil
}
