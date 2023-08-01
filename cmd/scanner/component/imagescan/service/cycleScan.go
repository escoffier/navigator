package service

import (
	"context"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

// 周期性扫描任务
func (s *ScanTaskSrv) CreateCycleScanTaskByConfig(ctx context.Context) error {
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Msg("CreateCycleScanTaskByConfig recover")
			}
		}()

		ticker := time.NewTicker(imagesecModel.ScanCycleCheckInternal)
		defer ticker.Stop()
		for {
			<-ticker.C
			config, err := s.scanConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Str("configType", imagesecModel.ConfigTypeNodeScanImage).
					Msg("CreateCycleScanTaskByConfig GetScanImageConfig")
				continue
			}

			add := config.ImageScanConfig.IsTimeToAddTask(imagesecModel.ScanCycleCheckInternal)
			logging.Get().Debug().Str("module", "imagescan").Bool("addScanTask", add).Msg("CreateCycleScanTaskByConfig")
			if !add {
				continue
			}
			logging.Get().Info().Str("module", "imagescan").Bool("addScanTask", add).Msg("CreateCycleScanTaskByConfig")
			param := imagesecModel.ImageSearchApiParam{
				ImageFromType: imagesecModel.ImageFromNode,
				ClusterKey:    config.ImageScanConfig.ScanCycle.ClusterKey,
			}
			taskInfo := imagesecModel.ImageScanTask{
				ImageFromType: imagesecModel.ImageFromNode,
				ScanType:      imagesecModel.CycleTrigger,
			}
			if err := s.CreateImageScanTask(ctx, param, taskInfo); err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("CreateCycleScanTaskByConfig CreateImageScanTask")
				continue
			}
			logging.Get().Info().Str("module", "imagescan").Str("scanType", imagesecModel.CycleTrigger).Msg("CreateCycleScanTaskByConfig CreateImageScanTask succeed")
		}
	}()

	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Msg("CreateCycleScanTaskByConfig recover")
			}
		}()

		ticker := time.NewTicker(imagesecModel.ScanCycleCheckInternal)
		defer ticker.Stop()
		for {
			<-ticker.C
			config, err := s.scanConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeRegScanImage)
			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Str("configType", imagesecModel.ConfigTypeRegScanImage).
					Msg("CreateCycleScanTaskByConfig GetScanImageConfig")
				continue
			}

			add := config.ImageScanConfig.IsTimeToAddTask(imagesecModel.ScanCycleCheckInternal)
			logging.Get().Debug().Str("module", "imagescan").Bool("addScanTask", add).Msg("CreateCycleScanTaskByConfig")
			if !add {
				continue
			}
			logging.Get().Info().Str("module", "imagescan").Bool("addScanTask", add).Msg("CreateCycleScanTaskByConfig")
			param := imagesecModel.ImageSearchApiParam{
				ImageFromType: imagesecModel.ImageFromRegistry,
				RegIds:        config.ImageScanConfig.ScanCycle.RegIds,
			}
			taskInfo := imagesecModel.ImageScanTask{
				ImageFromType: imagesecModel.ImageFromRegistry,
				ScanType:      imagesecModel.CycleTrigger,
			}
			if err := s.CreateImageScanTask(ctx, param, taskInfo); err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("CreateCycleScanTaskByConfig CreateImageScanTask")
				continue
			}
			logging.Get().Info().Str("module", "imagescan").Str("scanType", imagesecModel.CycleTrigger).Msg("CreateCycleScanTaskByConfig CreateImageScanTask succeed")
		}
	}()

	return nil
}
