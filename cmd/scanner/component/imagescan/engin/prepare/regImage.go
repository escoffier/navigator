package prepare

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/global"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imageCache "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type RegImagePrepare struct {
	ScanCachePath  string // 扫描中所有的临时文件存放目录
	LayerCachePath string
	TarFilename    string //  "layer.tar"
	Semaphore      *Semaphore
	Log            *scannerUtils.LogEvent
}

var regImagePrepareSinge *RegImagePrepare

func NewRegImagePreparer(scanCachePath string) *RegImagePrepare {
	if regImagePrepareSinge != nil {
		return regImagePrepareSinge
	}
	regImagePrepareSinge = &RegImagePrepare{
		LayerCachePath: "/FileServerCache/layerManage/data/",
		ScanCachePath:  scanCachePath,
		TarFilename:    "layer.tar",
		Semaphore:      NewSemaphore(int64(global.ScannerOpts.ParallelTaskNum * global.ScannerOpts.ParallelSubTaskNum)),
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("RegImagePrepare"),
			scannerUtils.WithModule(consts.ModuleImageScan),
		),
	}
	if global.ScannerOpts.ParallelExtractNum > 0 {
		regImagePrepareSinge.Semaphore = NewSemaphore(int64(global.ScannerOpts.ParallelExtractNum))
	}
	_ = os.MkdirAll(regImagePrepareSinge.ScanCachePath, os.ModePerm)
	return regImagePrepareSinge
}

// 解压一层就返回一层
// func (s *RegImagePrepare) PrepareImageLayer(ctx context.Context, prep *imagesecTypes.PrepareScan, out chan *imagesecTypes.ImageLayer) {
// 	s.Log.Info().Int("ParallelExtractNum", global.ScannerOpts.ParallelExtractNum).Msg("PrepareImageLayer")
// 	layers := make([]*imagesecTypes.ImageLayer, 0)
// 	for i := range prep.Layers {
// 		layers = append(layers, prep.Layers[i])
// 	}
//
// 	sort.Sort(imagesecTypes.ImageLayers(layers))
//
// 	// 并行解压
// 	for i := range layers {
// 		go func(ctx context.Context, prep *imagesecTypes.PrepareScan, ly *imagesecTypes.ImageLayer, out chan *imagesecTypes.ImageLayer) {
// 			err2 := s.PrepareLayerFile(ctx, prep, ly)
// 			if err2 != nil {
// 				s.Log.Err(err2).Interface("layer", ly).Str("subtask", prep.Subtask.LogStr()).Msg("PrepareScan")
// 				ly.NotReady = true
// 			}
// 			out <- ly
// 		}(ctx, prep, layers[i], out)
// 	}
//
// 	s.Log.Debug().Interface("prep", prep).Str("subtask", prep.Subtask.LogStr()).Msg("RegImagePrepare")
// 	return
// }

// 等待所有的都全部解压
// func (s *RegImagePrepare) PrepareImageLayer2(ctx context.Context, prep *imagesecTypes.PrepareScan, out chan *imagesecTypes.ImageLayer) {
// 	s.Log.Info().Int("ParallelExtractNum", global.ScannerOpts.ParallelExtractNum).Msg("PrepareImageLayer")
//
// 	layers := make([]*imagesecTypes.ImageLayer, 0)
// 	for i := range prep.Layers {
// 		layers = append(layers, prep.Layers[i])
// 	}
//
// 	sort.Sort(imagesecTypes.ImageLayers(layers))
//
// 	// 并行解压
// 	for i := range layers {
// 		go func(ctx context.Context, prep *imagesecTypes.PrepareScan, ly *imagesecTypes.ImageLayer, out chan *imagesecTypes.ImageLayer) {
// 			err2 := s.PrepareLayerFile(ctx, prep, ly)
// 			if err2 != nil {
// 				s.Log.Err(err2).Interface("layer", ly).Str("subtask", prep.Subtask.LogStr()).Msg("PrepareScan")
// 				ly.NotReady = true
// 			}
// 			out <- ly
// 		}(ctx, prep, layers[i], out)
// 	}
//
// 	s.Log.Debug().Interface("prep", prep).Str("subtask", prep.Subtask.LogStr()).Msg("RegImagePrepare")
// 	return
// }

// 会持续等待解压完成
func (s *RegImagePrepare) PrepareAllLayer(ctx context.Context, prep *imagesecTypes.PrepareScan) {
	start := time.Now().Unix()
	layers := make([]*imagesecTypes.ImageLayer, 0)
	for _, ly := range prep.Layers {
		if ly.NeedExtract {
			layers = append(layers, ly)
		}
	}

	sort.Sort(imagesecTypes.ImageLayers(layers))

	// 并行解压
	out := make(chan error)
	defer close(out)
	for i := range layers {
		go func(ctx context.Context, prep *imagesecTypes.PrepareScan, ly *imagesecTypes.ImageLayer, out chan error) {
			err2 := s.PrepareLayerFile(ctx, prep, ly)
			if err2 != nil {
				s.Log.Err(err2).Interface("layer", ly).Str("subtask", prep.Subtask.LogStr()).Msg("PrepareScan")
			}
			out <- err2
		}(ctx, prep, layers[i], out)
	}

	for i := 0; i < len(layers); i++ {
		err3 := <-out
		if err3 != nil {
			prep.Errors = append(prep.Errors, err3)
		}
	}
	s.Log.Info().Str("subtask", prep.Subtask.LogStr()).Int64("cost", time.Now().Unix()-start).
		Str(consts.ScanJobLogName, "PrepareLayerFile").Int("allLayerCnt", len(prep.Layers)).
		Int("extractLayer", len(layers)).Msg("scan job end")
	return
}

// 获取镜像元信息，并下载好 tar 包
func (s *RegImagePrepare) PrepareImageMate(ctx context.Context, sub imagesecTypes.ScanSubTask) *imagesecTypes.PrepareScan {

	prep := &imagesecTypes.PrepareScan{
		Subtask: sub,
		Layers:  make(map[string]*imagesecTypes.ImageLayer),
		Errors:  make([]error, 0),
	}

	rooDir, err := s.genRootDir(ctx, sub)
	if err != nil {
		s.Log.Err(err).Str(consts.SubtaskLogName, sub.LogStr()).Msg("genRootDir")
		prep.Errors = append(prep.Errors, err)
		return prep
	}

	prep.TaskRootDir = rooDir

	ta := prep.Subtask

	manifest, err := s.getManifest(ctx, ta)
	if err != nil {
		s.Log.Err(err).Str("subtask", ta.LogStr()).Msg("PrepareScan")
		prep.Errors = append(prep.Errors, err)
		return prep
	}

	prep.ImageManifest = manifest

	s.Log.Debug().Str("manifest.ImageDigest", manifest.ImageDigest).Str("Digest", manifest.V2.Config.Digest.String()).Msg("PrepareImageMate")

	if err := s.pullInspectLayer(ctx, prep, manifest.V2.Config.Digest.String()); err != nil {
		prep.Errors = append(prep.Errors, err)
		return prep
	}

	imageLayer := manifest.GenImageLayer()
	if len(imageLayer) == 0 {
		prep.Errors = append(prep.Errors, fmt.Errorf("not get image inspect"))
		return prep
	}

	for i := range imageLayer {
		ly := imageLayer[i]
		ly.OriginalTarFile = filepath.Join(s.LayerCachePath, ly.Digest, s.TarFilename)
		ly.LayerFilePath = filepath.Join(prep.TaskRootDir, scannerUtils.GetSimDigest(ly.Digest))
		ly.PreFix = filepath.Join(prep.TaskRootDir, scannerUtils.GetSimDigest(ly.Digest))
		ly.TarFilename = filepath.Join(prep.TaskRootDir, fmt.Sprintf("%s.tar", scannerUtils.GetSimDigest(ly.Digest)))

		prep.Layers[ly.Digest] = ly
	}

	s.findNeedPrepareLayer(ctx, prep)

	if err := s.PullImageLayer(ctx, prep); err != nil {
		prep.Errors = append(prep.Errors, err)
		return prep
	}

	// 有不同层，但是是一样的层级 ID，tensorsecurity/scan-report:ci
	return prep
}

// 深度扫描时，解压 tar 包
func (s *RegImagePrepare) PrepareLayerFile(ctx context.Context, prep *imagesecTypes.PrepareScan, ly *imagesecTypes.ImageLayer) error {
	// 如果不开启动深度扫描，则不需要解压文件
	if !prep.Subtask.DeepScan {
		return nil
	}

	if prep.Subtask.MalwareCache.In(ly.Digest) && prep.Subtask.WebshellCache.In(ly.Digest) {
		s.Log.Debug().Str("subtask", prep.Subtask.LogStr()).Str("layer", ly.Digest).Msg("layer in cache not need extract")
		return nil
	}

	// 支持并行解压
	s.Semaphore.Acquire()
	defer s.Semaphore.Release()

	s.Log.Debug().Str("subtask", prep.Subtask.LogStr()).Str("layer", ly.Digest).Msg("layer not in cache need extract")
	// linux 下不可以同时解压同一个文件,但是可以同时复制一个文件
	start := time.Now().Unix()
	if err2 := s.extractDockerTar3(ly.OriginalTarFile, ly.LayerFilePath); err2 != nil {
		s.Log.Info().Interface("layer", ly).Str("Err", err2.Error()).Msg("PrepareScan extractDockerTar1 try extractTarUseTar")
		// 说明格式不对，尝试直接用 tar 命令解压
		// 对应的Bug: https://project.feishu.cn/tensorsecurity/issue/detail/3003143912
		if err := s.copyFile(ctx, ly.OriginalTarFile, ly.TarFilename); err != nil {
			s.Log.Err(err).Interface("layer", ly).Msg("PrepareScan copyFile")
			return fmt.Errorf("extract tar file:%s,layerFilePath:%s", err2.Error(), ly.LayerFilePath)
		}
		if err := s.extractTarUseTar(ctx, ly.OriginalTarFile, ly.LayerFilePath); err != nil {
			s.Log.Err(err).Interface("layer", ly).Msg("PrepareScan extractTarUseTar")
			return fmt.Errorf("extract tar file:%s,layerFilePath:%s", err2.Error(), ly.LayerFilePath)
		}
	}

	s.Log.Debug().Str("subtask", prep.Subtask.LogStr()).Str("layer", ly.Digest).Int64("cost", time.Now().Unix()-start).
		Msg("scan job end Extract Layer success")

	return nil
}

func (s *RegImagePrepare) PullImageLayer(ctx context.Context, prep *imagesecTypes.PrepareScan) error {
	start := time.Now().Unix()

	client1, err := imageCache.NewLocalLayerManageClientT("/layer")
	if err != nil {
		s.Log.Err(err).Msg("new layer client error")
		return err
	}

	sub, reg, image := prep.Subtask, prep.Subtask.RegInfo, prep.Subtask.RegImageMeta

	out := make(chan *imagesecTypes.ImageLayer)
	defer close(out)

	lys := make([]*imagesecTypes.ImageLayer, 0)
	for i := range prep.Layers {
		ly := prep.Layers[i]
		if ly.NeedPull {
			s.Log.Debug().Str("subtask", prep.Subtask.LogStr()).Str("layer", ly.Digest).Msg("layer not in cache need pull")
			lys = append(lys, ly)
			continue
		}
		s.Log.Debug().Str("subtask", prep.Subtask.LogStr()).Str("layer", ly.Digest).Msg("layer in cache not need pull")
	}

	for i := 0; i < len(lys); i++ {
		go func(ctx context.Context, reg imagesecTypes.RegInfo, ly *imagesecTypes.ImageLayer, out chan *imagesecTypes.ImageLayer) {
			ly.OriginalTarFile = filepath.Join(s.LayerCachePath, ly.Digest, s.TarFilename)
			if _, _, err := client1.GetLayer(reg.Username, reg.Password, reg.Url, image.Repo, ly.Digest, true); err != nil {
				s.Log.Err(err).Interface("image", image).Msg("GetLayer")
				ly.NotReady = true
			}
			out <- ly
		}(ctx, reg, lys[i], out)
	}

	// 等待完成
	var notReady *imagesecTypes.ImageLayer
	for i := 0; i < len(lys); i++ {
		ou := <-out
		if ou.NotReady {
			notReady = ou
		}
	}

	if notReady != nil {
		return fmt.Errorf("image layer not ready:%s", notReady.Digest)
	}

	s.Log.Info().Str("subtask", sub.LogStr()).Int64("cost", time.Now().Unix()-start).
		Str(consts.ScanJobLogName, "PullLayer").Int("allLayerCnt", len(prep.Layers)).
		Int("pulledLayer", len(lys)).Msg("scan job end")
	return nil
}

func (s *RegImagePrepare) CleanUpScan(ctx context.Context, prep *imagesecTypes.PrepareScan) error {
	s.Log.Debug().Str("ImageName", prep.Subtask.RegImageMeta.ImageName()).Msg("CleanUpScan start")

	client1, err := imageCache.NewLocalLayerManageClientT("/layer")
	if err != nil {
		s.Log.Err(err).Msg("DeleteLayer")
		return err
	}
	if prep == nil {
		return nil
	}
	for _, ly := range prep.Layers {
		if !ly.NeedPull {
			continue
		}
		dig := scannerUtils.GetSha256Digest(ly.Digest)
		if err := client1.DeleteLayer(dig); err != nil {
			s.Log.Err(err).Str("layer", dig).Msg("delete layer failed")
			continue
		}
	}

	if prep.TaskRootDir == "" {
		return nil
	}
	_, err = os.Stat(prep.TaskRootDir)
	if err == nil {
		if err := os.RemoveAll(prep.TaskRootDir); err != nil {
			s.Log.Err(err).Str("TaskRootDir", prep.TaskRootDir).Msg("RemoveAll TaskRootDir")
			return err
		}
	}
	s.Log.Info().Str("ImageName", prep.Subtask.RegImageMeta.ImageName()).Str("path", prep.TaskRootDir).Msg("CleanUpScan end")
	return nil
}
