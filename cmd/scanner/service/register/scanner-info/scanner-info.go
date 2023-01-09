/*
scanner上报告信息，这一版本直接写数据库，后续把扫描器独立之后改成接口上报
*/

package scannerinfo

import (
	"context"
	"os"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	serviceName = "scanner-info"
)

type InfoUpdate struct {
	update component.ScannerInstanceInfoInterface
}

func (i *InfoUpdate) Start(ctx context.Context) error {
	// 执行上报scanner的信息
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.GetLogger().Error().Msg("SyncAllImage recover")
			}
		}()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			scannerVersion := os.Getenv("SOFT_VERSION")

			<-ticker.C

			if global.ScannerInstance == "" {
				logging.GetLogger().Info().Msg("CreateOrUpdateInstance global.ScannerInstance is empty ")
				continue
			}
			info := model.ScannerInstanceInfo{
				ClusterKey:      global.ClusterKey,
				ClusterName:     global.ClusterName,
				ScannerPodID:    global.ScannerPodID,
				ScannerVersion:  scannerVersion,
				ScannerInstance: global.ScannerInstance,
			}

			_, err := i.update.CreateOrUpdateInstance(ctx, info)
			if err != nil {
				logging.GetLogger().Err(err).Msg("CreateOrUpdateInstance service end")
				continue
			}
			logging.GetLogger().Debug().Msg("CreateOrUpdateInstance start success")
		}
	}()

	return nil
}

func (i *InfoUpdate) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
	logging.GetLogger().Info().Msg("image-sync register success")
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	scannerWrapperDb := store.GetScannerWrapperDb()
	s := component.NewScannerInstanceInfoSrv(
		store.NewScannerInstanceDao(scannerWrapperDb),
	)
	return &InfoUpdate{update: s}, nil
}
