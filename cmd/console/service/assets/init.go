package assets

import (
	"errors"
	"runtime/debug"
	"sync"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/image"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/kubemonitor"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/microseg"
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
	ov *AssetsInResourcesService,
	kbmSvc *kubemonitor.Service,
	tsRes *TensorResourcesService,
) (*assets.Watcher, error) {
	if ov == nil || postgre == nil || kbmSvc == nil {
		return nil, errors.New("arguments exist nil")
	}
	initOnce.Do(func() {
		logging.GetLogger().Info().Msgf("Init assets.Watcher: stack = %s", debug.Stack())
		wInstance = assets.NewWatcher()
		wInstance.AddCallback(ov)
		wInstance.AddCallback(image.NewAssetsImageAssociator(postgre))
		wInstance.AddCallback(microseg.NewResourcesListener(postgre))
		wInstance.AddCallback(kbmSvc.RiskMonitor())
		wInstance.AddCallback(tsRes)
	})
	return wInstance, nil
}
