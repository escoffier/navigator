package assets

import (
	"errors"
	"runtime/debug"
	"sync"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/onlinevulns"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	initOnce  sync.Once
	wInstance *assets.Watcher
)

// Watcher singleton
func Watcher(sa *ServiceAssetsService, ov *onlinevulns.OnlineVulnerabilitiesService) (*assets.Watcher, error) {
	if sa == nil || ov == nil {
		return nil, errors.New("arguments exist nil")
	}
	initOnce.Do(func() {
		logging.GetLogger().Info().Msgf("Init assets.Watcher: stack = %s", debug.Stack())
		wInstance = assets.NewWatcher()
		wInstance.AddCallback(sa)
		wInstance.AddCallback(ov)
	})
	return wInstance, nil
}
