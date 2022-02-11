package assets

import (
	"errors"
	"runtime/debug"
	"sync"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/image"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/kubemonitor"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/microseg"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

var (
	initOnce  sync.Once
	wInstance *assets.Watcher
)

// Watcher singleton
func Watcher(rdb *rdbtools.GormWrapper,
	redisCli *redis.Client,
	scannerURL string,
) (*assets.Watcher, error) {
	if rdb == nil || redisCli == nil || scannerURL == "" {
		return nil, errors.New("illegal argument")
	}
	initOnce.Do(func() {
		logging.GetLogger().Info().Msgf("Init assets.Watcher: stack = %s", debug.Stack())
		wInstance = assets.NewWatcher()
		wInstance.AddCallback(newPodResourcesService(redisCli, rdb))
		wInstance.AddCallback(microseg.NewResourcesListener(rdb))
		kbm, err := kubemonitor.NewService()
		if err == nil {
			wInstance.AddCallback(kbm.RiskMonitor())
		} else {
			logging.GetLogger().Err(err).Msg("init kube monitor error")
		}
		wInstance.AddCallback(newResourcesWatcher(rdb, scannerURL))
		wInstance.AddCallback(image.NewOnlineMonitor(rdb, scannerURL))
	})
	return wInstance, nil
}
