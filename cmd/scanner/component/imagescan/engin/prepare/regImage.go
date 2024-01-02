package prepare

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/docker/distribution/manifest/schema2"
	dockerarchive "github.com/docker/docker/pkg/archive"
	"go.uber.org/atomic"

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

func (s *RegImagePrepare) genRootDir(ctx context.Context, subtask imagesecTypes.ScanSubTask) (string, error) {
	// 每次任务的 ID 是不一样的，且只有失败的任务才可以重试,所以不会有误删除情况
	dir := filepath.Join(s.ScanCachePath, fmt.Sprintf("%d", subtask.SubTaskID))
	s.Log.Info().Str("taskRootPath", dir).Msg("genRootDir")
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return "", err
	}
	return dir, nil
}

func (s *RegImagePrepare) ImageScanJob(ctx context.Context, subtask imagesecTypes.ScanSubTask) *imagesecTypes.PrepareScan {
	prep := &imagesecTypes.PrepareScan{
		Subtask: subtask,
		Layers:  make(map[string]*imagesecTypes.ImageLayer),
	}
	s.Log.Info().Str(consts.SubtaskLogName, prep.Subtask.LogStr()).Str(consts.ScanJobLogName, "RegImagePrepare").Msg("scan job start")
	defer s.Log.Info().Str(consts.SubtaskLogName, prep.Subtask.LogStr()).Str(consts.ScanJobLogName, "RegImagePrepare").Msg("scan job end")

	rooDir, err := s.genRootDir(ctx, prep.Subtask)
	if err != nil {
		s.Log.Err(err).Str(consts.SubtaskLogName, subtask.LogStr()).Msg("genRootDir")
		prep.Errors = append(prep.Errors, err)
		return prep
	}

	prep.TaskRootDir = rooDir

	ta := subtask
	pullStart := time.Now().Unix()
	layers, err := s.PullImage(ctx, subtask, prep)
	if err != nil {
		s.Log.Err(err).Str("subtask", ta.LogStr()).Msg("PrepareScan")
		prep.Errors = append(prep.Errors, err)
		return prep
	}
	s.Log.Info().Str(consts.SubtaskLogName, prep.Subtask.LogStr()).Str(consts.ScanJobLogName, "PullImage").
		Int64("cost", time.Now().Unix()-pullStart).Msg("scan job end")
	// 因为第一个不是镜像层文件,是镜像inspect 的信息
	// 糟糕的设计，因为这个设计，后面如果和节点镜像整合时会有麻烦
	if len(layers) > 0 {
		layers = layers[1:]
	}
	pullStart = time.Now().Unix()

	// 并行解压
	out := make(chan error)
	defer close(out)
	for i := range layers {
		go func(ctx context.Context, prep *imagesecTypes.PrepareScan, ly *imagesecTypes.ImageLayer, out chan error) {
			err2 := s.PrepareFile(ctx, prep, ly)
			if err2 != nil {
				s.Log.Err(err2).Interface("layer", ly).Str("subtask", ta.LogStr()).Msg("PrepareScan")
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

	s.Log.Info().Str(consts.SubtaskLogName, prep.Subtask.LogStr()).Str(consts.ScanJobLogName, "PrepareFile").
		Int64("cost", time.Now().Unix()-pullStart).Msg("scan job end")

	for i := range layers {
		prep.Layers[layers[i].Digest] = layers[i]
	}

	s.Log.Debug().Interface("prep", prep).Str("subtask", subtask.LogStr()).Msg("RegImagePrepare")
	return prep
}

// func (s *RegImagePrepare) ImageScanJob2(ctx context.Context, subtask imagesecTypes.ScanSubTask) *imagesecTypes.PrepareScan {
// 	prep := &imagesecTypes.PrepareScan{
// 		Subtask:   subtask,
// 		Layers:    make(map[string]*imagesecTypes.ImageLayer),
// 		LayerChan: make(chan *imagesecTypes.ImageLayer),
// 	}
// 	rooDir, err := s.genRootDir(ctx, subtask)
// 	if err != nil {
// 		s.Log.Err(err).Str(consts.SubtaskLogName, subtask.LogStr()).Msg("genRootDir")
// 		prep.Errors = append(prep.Errors, err)
// 	}
// 	prep.TaskRootDir = rooDir
//
// 	ta := subtask
// 	pullStart := time.Now().Unix()
// 	layers, err := s.PullImage(ctx, subtask, prep)
// 	if err != nil {
// 		s.Log.Err(err).Str("subtask", ta.LogStr()).Msg("PrepareScan")
// 		prep.Errors = append(prep.Errors, err)
// 	}
// 	s.Log.Info().Str(consts.SubtaskLogName, prep.Subtask.LogStr()).Str(consts.ScanJobLogName, "PullImage").
// 		Int64("cost", time.Now().Unix()-pullStart).Msg("scan job end")
//
// 	go func() {
// 		defer close(prep.LayerChan)
// 		out := make(chan error)
// 		defer close(out)
// 		for i := range layers {
// 			ly := layers[i]
//
// 			go func(ctx context.Context, prep *imagesecTypes.PrepareScan, ly *imagesecTypes.ImageLayer, out chan error) {
// 				err2 := s.PrepareFile(ctx, prep, ly)
// 				if err2 != nil {
// 					s.Log.Err(err2).Interface("layer", ly).Str("subtask", ta.LogStr()).Msg("PrepareScan")
// 				}
// 				out <- err2
// 			}(ctx, prep, ly, out)
// 		}
//
// 		for i := 0; i < len(layers); i++ {
// 			err3 := <-out
// 			if err3 != nil {
// 				prep.Errors = append(prep.Errors, err3)
// 			}
// 		}
// 	}()
// 	return prep
// }

// 这里是最慢的，而且很容易OOM
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

	pullStart := time.Now().Unix()
	// linux 下不可以同时解压同一个文件,但是可以同时复制一个文件
	// if err := s.CopyFile(ctx, ly.OriginalTarFile, ly.TarFilename); err != nil {
	// 	s.Log.Err(err).Interface("layer", ly).Msg("PrepareScan CopyFile")
	// 	return fmt.Errorf("copy file:%s,TarFilename:%s", err.Error(), ly.TarFilename)
	// }
	// s.Log.Info().Str("digest", ly.Digest).Str(consts.ScanJobLogName, "CopyFile").
	// 	Int64("cost", time.Now().Unix()-pullStart).Msg("scan job end")

	pullStart = time.Now().Unix()
	if err2 := s.ExtractDockerTar(ly.OriginalTarFile, ly.LayerFilePath); err2 != nil {
		s.Log.Err(err2).Interface("layer", ly).Msg("PrepareScan ExtractDockerTar")
		return fmt.Errorf("extract tar file:%s,layerFilePath:%s", err2.Error(), ly.LayerFilePath)
	}
	s.Log.Info().Str("digest", ly.Digest).Str(consts.ScanJobLogName, "ExtractDockerTar").
		Int64("cost", time.Now().Unix()-pullStart).Msg("scan job end ExtractFile success")

	return nil
}

func (s *RegImagePrepare) PullImage(ctx context.Context, subtask imagesecTypes.ScanSubTask, res *imagesecTypes.PrepareScan) ([]*imagesecTypes.ImageLayer, error) {

	layers := make([]*imagesecTypes.ImageLayer, 0)
	client, err := imageCache.NewLocalLayerManageClientT("/manifest")
	if err != nil {
		s.Log.Err(err).Msg("new manifest client error")
		return layers, err
	}

	client1, err := imageCache.NewLocalLayerManageClientT("/layer")
	if err != nil {
		s.Log.Err(err).Msg("new layer client error")
		return layers, err
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

	s.Log.Debug().Strs("layers", lys).Msg("GenLayerDigest")
	// 检测所有的层是否都在缓存中，如果不在缓存中，缓存会自动pull
	for i := range lys {
		if _, _, err := client1.GetLayer(reg.Username, reg.Password, reg.Url, image.Repo, lys[i], true); err != nil {
			s.Log.Err(err).Interface("image", image).Msg("GetLayer")
			// 保证能pull所有层级
			return nil, err
		}
		srcTarFile := filepath.Join(s.LayerCachePath, lys[i], s.TarFilename)

		layers = append(layers, &imagesecTypes.ImageLayer{
			Digest:          lys[i],
			OriginalTarFile: srcTarFile,
		})
	}

	return layers, nil
}

func (s *RegImagePrepare) CopyFile(ctx context.Context, src string, des string) error {
	ctx, cancelFunc := context.WithTimeout(ctx, 1*time.Minute)

	defer cancelFunc()

	cmd := exec.CommandContext(ctx, "cp", "-f", src, des)

	// 设置命令的输出和错误输出
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	s.Log.Debug().Strs("cmd", cmd.Args).Msg("CopyFile")
	// 执行命令
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func (s *RegImagePrepare) ExtractTar(ctx context.Context, tarFile, targetDir string) error {

	_ = os.RemoveAll(targetDir)
	_ = os.MkdirAll(targetDir, os.ModePerm)

	ctx, cancelFunc := context.WithTimeout(ctx, 5*time.Minute)

	defer cancelFunc()
	cmd := exec.CommandContext(ctx, "tar", "-xf", tarFile, "-C", targetDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	s.Log.Debug().Strs("cmd", cmd.Args).Msg("ExtractDockerTar")
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func (s *RegImagePrepare) CleanUp(ctx context.Context, pre *imagesecTypes.PrepareScan) error {
	s.Log.Debug().Str("ImageName", pre.Subtask.RegImageMeta.ImageName()).Msg("CleanUp start")
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
	s.Log.Info().Str("ImageName", pre.Subtask.RegImageMeta.ImageName()).Str("path", pre.TaskRootDir).Msg("CleanUp end")
	return nil
}

// 测试用时更多
func (s *RegImagePrepare) ExtractDockerTar2(tarFile, destDir string) error {
	_ = filepath.Clean(destDir)
	if err := os.MkdirAll(destDir, os.ModePerm); err != nil {
		return err
	}
	file, err := os.Open(tarFile)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	// 不能使用自带的包直接解压，一定得有这一步
	decompressStreamReader, err := dockerarchive.DecompressStream(file)
	if err != nil {
		s.Log.Err(err).Str("tarFile", tarFile).Str("destDir", destDir).Msg("ExtractDockerTar")
		return err
	}
	defer func() { _ = decompressStreamReader.Close() }()
	// 直接调用 docker 提供的方法
	if _, err := dockerarchive.UnpackLayer(destDir, decompressStreamReader, nil); err != nil {
		s.Log.Err(err).Str("tarFile", tarFile).Str("destDir", destDir).Msg("ExtractDockerTar")
		return err
	}
	s.Log.Debug().Str("tarFile", tarFile).Str("destDir", destDir).Msg("ExtractDockerTar success")
	return nil
}

func (s *RegImagePrepare) ExtractDockerTar(tarFile, destDir string) error {
	_ = filepath.Clean(destDir)
	if err := os.MkdirAll(destDir, os.ModePerm); err != nil {
		return err
	}

	file, err := os.Open(tarFile)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	// 不能使用自带的包直接解压，一定得有这一步
	decompressStreamReader, err := dockerarchive.DecompressStream(file)
	if err != nil {
		s.Log.Err(err).Str("tarFile", tarFile).Str("destDir", destDir).Msg("ExtractDockerTar")
		return err
	}

	defer func() { _ = decompressStreamReader.Close() }()

	tarReader := tar.NewReader(decompressStreamReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			s.Log.Err(err).Str("tarFile", tarFile).Str("destDir", destDir).Msg("ExtractDockerTar tarReader")
			return err
		}

		target := filepath.Join(destDir, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.ModePerm); err != nil {
				s.Log.Err(err).Str("tarFile", tarFile).Str("target", target).Msg("ExtractDockerTar MkdirAll")
				return err
			}
		case tar.TypeReg:
			if err := scannerUtils.SaveFileFromTarReader(tarReader, target); err != nil {
				s.Log.Err(err).Str("tarFile", tarFile).Str("target", target).Msg("ExtractDockerTar writeFile")
				continue
			}
		}
	}
	s.Log.Debug().Str("tarFile", tarFile).Str("destDir", destDir).Msg("ExtractDockerTar success")
	return nil
}

var webshellMap = map[string]bool{
	".php":      true,
	".php5":     true,
	".php4":     true,
	".asp":      true,
	".aspx":     true,
	".asmx":     true,
	".ashx":     true,
	".jsp":      true,
	".jspa":     true,
	".jspx":     true,
	".jspf":     true,
	".cer":      true,
	".htaccess": true,
}

// 判断webshell文件后缀是否是给定的后缀
func FilterWebshell(fi os.FileInfo) bool {
	ext := filepath.Ext(fi.Name())
	return webshellMap[ext]
}

// 判断webshell文件后缀是否是给定的后缀
func FilterMalware(fi os.FileInfo) bool {
	/*
		这几个目录加白
		/proc: 包含系统进程信息。
		/sys: 包含与内核和硬件相关的信息。
		/dev: 包含设备文件。
		/run: 包含运行时信息。
		/var/log: 包含系统和应用程序日志
	*/
	dn := fi.Name()
	if !strings.HasPrefix(dn, "/") {
		dn = "/" + dn
	}

	if strings.HasPrefix(dn, "/proc") || strings.HasPrefix(dn, "/sys") ||
		strings.HasPrefix(dn, "/dev") || strings.HasPrefix(dn, "/var/log") {
		return false
	}

	return true
}

type Semaphore struct {
	MG    sync.Locker
	Max   int64
	value *atomic.Int64
}

func NewSemaphore(initialValue int64) *Semaphore {
	s := &Semaphore{
		MG:    &sync.Mutex{},
		value: atomic.NewInt64(0),
		Max:   initialValue,
	}
	return s
}

func (s *Semaphore) Acquire() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		s.MG.Lock()
		if s.value.Load() < s.Max {
			s.value.Add(1)
			s.MG.Unlock()
			return
		}
		s.MG.Unlock()
		<-ticker.C
	}
}

func (s *Semaphore) Release() {
	s.MG.Lock()
	defer s.MG.Unlock()
	s.value.Dec()
}
