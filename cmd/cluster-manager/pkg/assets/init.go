package assets

import (
	"errors"
	"runtime/debug"
	"sync"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg/image"
	"gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg/kubemonitor"
	"gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg/microseg"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

var (
	initOnce  sync.Once
	wInstance *assets.Watcher
)

// Watcher singleton
func Watcher(postgre *rdbtools.GormWrapper,
	redisCli *redis.Client,
	scannerURL string,
) (*assets.Watcher, error) {
	if postgre == nil || redisCli == nil || scannerURL == "" {
		return nil, errors.New("illegal argument")
	}
	initOnce.Do(func() {
		logging.GetLogger().Info().Msgf("Init assets.Watcher: stack = %s", debug.Stack())
		wInstance = assets.NewWatcher()
		wInstance.AddCallback(newPodResourcesService(redisCli, postgre))
		wInstance.AddCallback(microseg.NewResourcesListener(postgre))
		kbm, err := kubemonitor.NewService()
		if err == nil {
			wInstance.AddCallback(kbm.RiskMonitor())
		} else {
			logging.GetLogger().Err(err).Msg("init kube monitor error")
		}
		wInstance.AddCallback(newResourcesWatcher(postgre, scannerURL))
		wInstance.AddCallback(image.NewOnlineMonitor(postgre, scannerURL))
	})
	return wInstance, nil
}
