package prepare

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/docker/distribution/manifest/schema2"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/global"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imageCache "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
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
func (s *RegImagePrepare) PrepareImageLayer(ctx context.Context, prep *imagesecTypes.PrepareScan, out chan *imagesecTypes.ImageLayer) {
	s.Log.Info().Int("ParallelExtractNum", global.ScannerOpts.ParallelExtractNum).Msg("PrepareImageLayer")
	layers := make([]*imagesecTypes.ImageLayer, 0)
	for i := range prep.Layers {
		layers = append(layers, prep.Layers[i])
	}
	sort.Sort(imagesecTypes.ImageLayers(layers))

	// 并行解压
	for i := range layers {
		go func(ctx context.Context, prep *imagesecTypes.PrepareScan, ly *imagesecTypes.ImageLayer, out chan *imagesecTypes.ImageLayer) {
			err2 := s.PrepareFile(ctx, prep, ly)
			if err2 != nil {
				s.Log.Err(err2).Interface("layer", ly).Str("subtask", prep.Subtask.LogStr()).Msg("PrepareScan")
				ly.NotReady = true
			}
			out <- ly
		}(ctx, prep, layers[i], out)
	}

	s.Log.Debug().Interface("prep", prep).Str("subtask", prep.Subtask.LogStr()).Msg("RegImagePrepare")
	return
}

// 会持续等待解压完成
func (s *RegImagePrepare) ImageScanJob(ctx context.Context, subtask imagesecTypes.ScanSubTask) *imagesecTypes.PrepareScan {
	prep := s.PrepareImageMate(ctx, subtask)

	start := time.Now().Unix()
	s.logScanStart(prep)
	defer s.logScanEnd(start, prep)

	layers := make([]*imagesecTypes.ImageLayer, 0)
	for i := range prep.Layers {
		layers = append(layers, prep.Layers[i])
	}
	sort.Sort(imagesecTypes.ImageLayers(layers))

	// 并行解压
	out := make(chan error)
	defer close(out)
	for i := range layers {
		go func(ctx context.Context, prep *imagesecTypes.PrepareScan, ly *imagesecTypes.ImageLayer, out chan error) {
			err2 := s.PrepareFile(ctx, prep, ly)
			if err2 != nil {
				s.Log.Err(err2).Interface("layer", ly).Str("subtask", subtask.LogStr()).Msg("PrepareScan")
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
	return prep
}

// 获取镜像元信息，并下载好 tar 包
func (s *RegImagePrepare) PrepareImageMate(ctx context.Context, subtask imagesecTypes.ScanSubTask) *imagesecTypes.PrepareScan {

	prep := &imagesecTypes.PrepareScan{
		Subtask: subtask,
		Layers:  make(map[string]*imagesecTypes.ImageLayer),
		Errors:  make([]error, 0),
	}

	rooDir, err := s.genRootDir(ctx, subtask)
	if err != nil {
		s.Log.Err(err).Str(consts.SubtaskLogName, subtask.LogStr()).Msg("genRootDir")
		prep.Errors = append(prep.Errors, err)
		return prep
	}

	prep.TaskRootDir = rooDir

	ta := prep.Subtask

	layers, err := s.PullImage(ctx, ta, prep)
	if err != nil {
		s.Log.Err(err).Str("subtask", ta.LogStr()).Msg("PrepareScan")
		prep.Errors = append(prep.Errors, err)
		return prep
	}

	prep.Layers = layers
	// 有不同层，但是是一样的层级 ID，tensorsecurity/scan-report:ci
	return prep
}

func (s *RegImagePrepare) PrepareFile(ctx context.Context, prep *imagesecTypes.PrepareScan, ly *imagesecTypes.ImageLayer) error {
	// 如果不开启动深度扫描，则不需要解压文件
	if !prep.Subtask.DeepScan {
		return nil
	}
	ly.LayerFilePath = filepath.Join(prep.TaskRootDir, scannerUtils.GetSimDigest(ly.Digest))
	ly.PreFix = filepath.Join(prep.TaskRootDir, scannerUtils.GetSimDigest(ly.Digest))
	ly.TarFilename = filepath.Join(prep.TaskRootDir, fmt.Sprintf("%s.tar", scannerUtils.GetSimDigest(ly.Digest)))

	if prep.Subtask.MalwareCache.In(ly.Digest) && prep.Subtask.WebshellCache.In(ly.Digest) {
		s.Log.Info().Str("digest", ly.Digest).Msg("PrepareScan in cache do not need PrepareFile")
		return nil
	}

	// 支持并行解压
	s.Semaphore.Acquire()
	defer s.Semaphore.Release()

	// linux 下不可以同时解压同一个文件,但是可以同时复制一个文件
	start := time.Now().Unix()
	if err2 := s.extractDockerTar3(ly.OriginalTarFile, ly.LayerFilePath); err2 != nil {
		s.Log.Err(err2).Interface("layer", ly).Msg("PrepareScan extractDockerTar1")
		return fmt.Errorf("extract tar file:%s,layerFilePath:%s", err2.Error(), ly.LayerFilePath)
	}

	s.Log.Info().Int64("cost", time.Now().Unix()-start).Str("subtask", prep.Subtask.LogStr()).
		Msg("scan job end ExtractFile Layer success")

	return nil
}

func (s *RegImagePrepare) PullImage(ctx context.Context, subtask imagesecTypes.ScanSubTask, res *imagesecTypes.PrepareScan) (map[string]*imagesecTypes.ImageLayer, error) {
	start := time.Now().Unix()

	client, err := imageCache.NewLocalLayerManageClientT("/manifest")
	if err != nil {
		s.Log.Err(err).Msg("new manifest client error")
		return nil, err
	}

	client1, err := imageCache.NewLocalLayerManageClientT("/layer")
	if err != nil {
		s.Log.Err(err).Msg("new layer client error")
		return nil, err
	}

	manifestV1 := new(model.ManifestV1)

	v1v2 := &imagesecTypes.ManifestV2AndV1{}
	reg := subtask.RegInfo
	image := subtask.RegImageMeta

	manifestStr, err := client.GetManifest(reg.Username, reg.Password, reg.Url, image.Repo, image.Tag, true)
	manifestV2 := schema2.DeserializedManifest{}

	if err := manifestV2.UnmarshalJSON([]byte(manifestStr)); err != nil {
		s.Log.Err(err).Interface("image", image).Msg("get manifestV2")
	} else {
		v1v2.V2 = &manifestV2
		s.Log.Info().Interface("image", image).Msg("get manifestV2")
	}
	if v1v2.V2 == nil {
		if err := json.Unmarshal([]byte(manifestStr), manifestV1); err == nil && manifestV1.Name != "" {
			v1v2.V1 = manifestV1
			s.Log.Info().Str("image", subtask.RegImageMeta.ImageName()).Msg("get manifestV1")
		} else {
			s.Log.Err(err).Interface("image", image).Msg("get manifestV1")
		}
	}

	if v1v2.V1 == nil && v1v2.V2 == nil {
		s.Log.Err(err).Interface("image", image).Msg("not get manifestV1 and v2")
		res.UserDockerCli = true
		return nil, fmt.Errorf("not get manifest")
		// fixme 暂时不管
		// _, err := getInspectInfo(reg.Url, reg.Username, reg.PasswordString, image.GetDockerPullImageName())
		// if err != nil {
		// 	return prepare, errors.WithMessage(err, "docker client not get manifest,and docker pull not get manifest")
		// }
	}

	lys := imagesecTypes.GenLayerDigest(v1v2)
	if len(lys) == 0 {
		return nil, fmt.Errorf("not get imageLayer")
	}

	ly := lys[0]
	ly.OriginalTarFile = filepath.Join(s.LayerCachePath, ly.Digest, s.TarFilename)
	if _, _, err := client1.GetLayer(reg.Username, reg.Password, reg.Url, image.Repo, ly.Digest, true); err != nil {
		s.Log.Err(err).Interface("image", image).Msg("GetLayer")
		return nil, err
	}
	// 要特别注意
	// 因为第一个不是镜像层文件,是镜像inspect 的信息
	// 糟糕的设计，因为这个设计，后面如果和节点镜像整合时会有麻烦
	lys = lys[1:]
	s.Log.Debug().Interface("layers", lys).Msg("GenLayerDigest")
	// 检测所有的层是否都在缓存中，如果不在缓存中，缓存会自动pull
	out := make(chan *imagesecTypes.ImageLayer)
	defer close(out)

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
	layers := make(map[string]*imagesecTypes.ImageLayer)
	for i := 0; i < len(lys); i++ {
		ou := <-out
		if ou.Digest == "" {
			continue
		}
		layers[ou.Digest] = ou
	}

	for i := range layers {
		if layers[i].NotReady {
			return nil, fmt.Errorf("image layer not ready:%s", layers[i].Digest)
		}
	}

	s.Log.Info().Str(consts.SubtaskLogName, subtask.LogStr()).Int64("cost", time.Now().Unix()-start).
		Str(consts.ScanJobLogName, "PullImage").Int("layerCnt", len(layers)).Msg("scan job end")
	return layers, nil
}

func (s *RegImagePrepare) CleanUpScan(ctx context.Context, pre *imagesecTypes.PrepareScan) error {
	s.Log.Debug().Str("ImageName", pre.Subtask.RegImageMeta.ImageName()).Msg("CleanUpScan start")
	client1, err := imageCache.NewLocalLayerManageClientT("/layer")
	if err != nil {
		s.Log.Err(err).Msg("DeleteLayer")
		return err
	}
	for _, lay := range pre.Layers {
		dig := scannerUtils.GetSha256Digest(lay.Digest)
		if err := client1.DeleteLayer(dig); err != nil {
			s.Log.Err(err).Str("layer", dig).Msg("delete layer failed")
			continue
		}
	}

	if pre == nil || pre.TaskRootDir == "" {
		return nil
	}
	if err := os.RemoveAll(pre.TaskRootDir); err != nil {
		s.Log.Err(err).Str("TaskRootDir", pre.TaskRootDir).Msg("RemoveAll TaskRootDir")
		return err
	}
	s.Log.Info().Str("ImageName", pre.Subtask.RegImageMeta.ImageName()).Str("path", pre.TaskRootDir).Msg("CleanUpScan end")
	return nil
}
