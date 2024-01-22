package clean

import (
	"context"
	"os"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imageCache "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

//  扫描之后的清理工作

type ScanClear struct {
	Log *scannerUtils.LogEvent
}

var clearSinge *ScanClear

func NewScanClear() *ScanClear {
	if clearSinge != nil {
		return clearSinge
	}

	clearSinge = &ScanClear{Log: scannerUtils.NewLogEvent(
		scannerUtils.WithSubModule("ScanClear"),
		scannerUtils.WithModule(consts.ModuleImageScan),
	)}
	return clearSinge
}

func (s *ScanClear) Clear(ctx context.Context, pre *imagesecTypes.PrepareScan) imagesecTypes.ScanJobResult {
	start := time.Now().Unix()
	s.logScanStart(pre)
	defer s.logScanEnd(start, pre)

	res := imagesecTypes.ScanJobResult{}

	_ = s.deleteCacheFile(ctx, pre)
	_ = s.reduceLayerQuote(ctx, pre)
	return res
}

func (s *ScanClear) deleteCacheFile(ctx context.Context, pre *imagesecTypes.PrepareScan) error {
	if pre == nil {
		s.Log.Info().Msg("not clean up scan data,pre is nil")
		return nil
	}
	if pre.TaskRootDir == "" {
		s.Log.Info().Str("TaskRootDir", pre.TaskRootDir).Msg("not clean up scan data")
		return nil
	}
	_, err := os.Stat(pre.TaskRootDir)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	if err := os.RemoveAll(pre.TaskRootDir); err != nil {
		s.Log.Err(err).Str("TaskRootDir", pre.TaskRootDir).Msg("not clean up scan cache data")
		return err
	}
	s.Log.Info().Str("TaskRootDir", pre.TaskRootDir).Msg("clean up scan cache data")
	return nil
}

func (s *ScanClear) reduceLayerQuote(ctx context.Context, pre *imagesecTypes.PrepareScan) error {
	client1, err := imageCache.NewLocalLayerManageClientT("/layer")
	if err != nil {
		s.Log.Err(err).Msg("NewLocalLayerManageClientT")
		return err
	}
	for ly := range pre.Layers {
		if !pre.Layers[ly].NeedPull {
			continue
		}
		if err := client1.DeleteLayer(scannerUtils.GetSha256Digest(ly)); err != nil {
			s.Log.Err(err).Str("layer", ly).Msg("DeleteLayer")
			continue
		}
	}
	return nil
}

func (s *ScanClear) logScanEnd(start int64, pre *imagesecTypes.PrepareScan) {
	s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).
		Int64("cost", time.Now().Unix()-start).Msg("scan job end")
}

func (s *ScanClear) logScanStart(pre *imagesecTypes.PrepareScan) {
	s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).Msg("scan job start")
}
