package service

import (
	"context"
	"time"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

// 周期性扫描任务
func (s *ScanTaskSrv) CreateCycleScanTaskByConfig(ctx context.Context) error {
	go func() {
		defer func() {
			if err := recover(); err != nil {
				s.Log.Error().Msg("CreateCycleScanTaskByConfig recover")
			}
		}()

		ticker := time.NewTicker(imagesecModel.ScanCycleCheckInternal)
		defer ticker.Stop()
		for {
			<-ticker.C
			config, err := s.scanConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
			if err != nil {
				s.Log.Err(err).Str("configType", imagesecModel.ConfigTypeNodeScanImage).
					Msg("CreateCycleScanTaskByConfig GetScanImageConfig")
				continue
			}

			add := config.ImageScanConfig.IsTimeToAddTask(imagesecModel.ScanCycleCheckInternal)
			s.Log.Debug().Bool("addScanTask", add).Msg("CreateCycleScanTaskByConfig")
			if !add {
				continue
			}
			s.Log.Info().Bool("addScanTask", add).Msg("CreateCycleScanTaskByConfig")
			param := imagesecModel.ImageSearchApiParam{
				ImageFromType: imagesecModel.ImageFromNode,
				ClusterKey:    config.ImageScanConfig.ScanCycle.ClusterKey,
			}
			taskInfo := imagesecModel.ImageScanTask{
				ImageFromType: imagesecModel.ImageFromNode,
				ScanType:      imagesecModel.CycleTrigger,
			}
			if err := s.CreateImageScanTask(ctx, param, taskInfo); err != nil {
				s.Log.Err(err).Msg("CreateCycleScanTaskByConfig CreateImageScanTask")
				continue
			}
			s.Log.Info().Str("scanType", imagesecModel.CycleTrigger).Msg("CreateCycleScanTaskByConfig CreateImageScanTask succeed")
		}
	}()

	go func() {
		defer func() {
			if err := recover(); err != nil {
				s.Log.Error().Msg("CreateCycleScanTaskByConfig recover")
			}
		}()

		ticker := time.NewTicker(imagesecModel.ScanCycleCheckInternal)
		defer ticker.Stop()
		for {
			<-ticker.C
			config, err := s.scanConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeRegScanImage)
			if err != nil {
				s.Log.Err(err).Str("configType", imagesecModel.ConfigTypeRegScanImage).
					Msg("CreateCycleScanTaskByConfig GetScanImageConfig")
				continue
			}

			add := config.ImageScanConfig.IsTimeToAddTask(imagesecModel.ScanCycleCheckInternal)
			s.Log.Debug().Bool("addScanTask", add).Msg("CreateCycleScanTaskByConfig")
			if !add {
				continue
			}
			s.Log.Info().Bool("addScanTask", add).Msg("CreateCycleScanTaskByConfig")
			param := imagesecModel.ImageSearchApiParam{
				ImageFromType: imagesecModel.ImageFromRegistry,
				RegIds:        config.ImageScanConfig.ScanCycle.RegIds,
			}
			taskInfo := imagesecModel.ImageScanTask{
				ImageFromType: imagesecModel.ImageFromRegistry,
				ScanType:      imagesecModel.CycleTrigger,
			}
			if err := s.CreateImageScanTask(ctx, param, taskInfo); err != nil {
				s.Log.Err(err).Msg("CreateCycleScanTaskByConfig CreateImageScanTask")
				continue
			}
			s.Log.Info().Str("scanType", imagesecModel.CycleTrigger).Msg("CreateCycleScanTaskByConfig CreateImageScanTask succeed")
		}
	}()

	return nil
}
