package prepare

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/distribution/manifest/schema2"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	imageCache "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type ScanPrepare struct {
	CacheLayerPath   string
	RootPath         string
	TarFilename      string //  "layer.tar"
	ImageTarDirName  string //  "tar"
	ImageDataDirName string //  "data"
}

func NewPrepareImageScan() *ScanPrepare {
	s := &ScanPrepare{
		CacheLayerPath:   "/FileServerCache/layerManage/data/",
		TarFilename:      "layer.tar",
		RootPath:         "/Imagescan/",
		ImageTarDirName:  "tar",
		ImageDataDirName: "data",
	}
	// 新建目录
	return s
}

func (s *ScanPrepare) GenTarDir(ctx context.Context, subtask imagesecTypes.ScanSubTask) string {
	tarPath := filepath.Join(s.RootPath, fmt.Sprintf("%d", subtask.SubTaskID), s.ImageTarDirName)
	return tarPath
}

func (s *ScanPrepare) GenRootDir(ctx context.Context, subtask imagesecTypes.ScanSubTask) string {
	// 每次任务的 ID 是不一样的，且只有失败的任务才可以重试,所以才不会有误删除情况
	rootDir := filepath.Join(s.RootPath, fmt.Sprintf("%d", subtask.SubTaskID), s.ImageDataDirName)
	return rootDir
}

func (s *ScanPrepare) PrepareFile(ctx context.Context, subtask imagesecTypes.ScanSubTask, res *types.PrepareScan) error {
	if !subtask.DeepScan {
		// 未开启深度扫描，不用复制文件
		return nil
	}

	tarPath := s.GenTarDir(ctx, subtask)
	rootDir := s.GenRootDir(ctx, subtask)

	if err := os.MkdirAll(tarPath, os.ModeDir); err != nil {
		return err
	}
	if err := os.MkdirAll(rootDir, os.ModeDir); err != nil {
		return err
	}
	for i := range res.Layers {
		dig := res.Layers[i].Digest
		digestTarPath := filepath.Join(tarPath, GetSimDigest(dig))
		tarFile := filepath.Join(digestTarPath, s.TarFilename)
		unzipPath := filepath.Join(rootDir, GetSimDigest(dig))

		res.Layers[i].TarFile = tarFile
		res.Layers[i].UnzipPath = unzipPath

		if err := os.MkdirAll(digestTarPath, os.ModeDir); err != nil {
			return err
		}
		if err := os.MkdirAll(unzipPath, os.ModeDir); err != nil {
			return err
		}

		if err := CopyFile(ctx, res.Layers[i].OriginalTarFile, tarFile); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Str("tarFile", tarFile).
				Str("OriginalTarFile", res.Layers[i].OriginalTarFile).Msg("PrepareScan CopyFile")
			res.Errs = append(res.Errs, fmt.Errorf("can not copy file:%s", tarFile))
			return err
		}

		if err := ExtractTar(ctx, tarFile, unzipPath); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Str("tarFile", tarFile).
				Str("unzipPath", unzipPath).Msg("PrepareScan ExtractTar")
			res.Errs = append(res.Errs, fmt.Errorf("can not extract file:%s", tarFile))
			return err
		}

		files, err := s.Collect(ctx, unzipPath, CommonFilter, res)
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Str("tarFile", tarFile).
				Str("unzipPath", unzipPath).Msg("PrepareScan Collect")
			continue
		}
		res.LayerFile[dig] = files
	}

	return nil
}

func (s *ScanPrepare) PullImage(ctx context.Context, subtask imagesecTypes.ScanSubTask, res *types.PrepareScan) ([]types.ImageLayer, error) {

	layers := make([]types.ImageLayer, 0)
	client, err := imageCache.NewLocalLayerManageClientT("/manifest")
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("new manifest client error")
		return layers, err
	}

	client1, err := imageCache.NewLocalLayerManageClientT("/layer")
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("new layer client error")
		return layers, err
	}

	manifestV1 := new(model.ManifestV1)

	v1v2 := types.ManifestV2AndV1{}
	reg := subtask.RegInfo
	image := subtask.RegImageMeta

	manifestStr, err := client.GetManifest(reg.Username, reg.Password, reg.Url, image.Repo, image.Tag, true)
	manifestV2 := schema2.DeserializedManifest{}

	if err := manifestV2.UnmarshalJSON([]byte(manifestStr)); err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("image", image).Msg("get manifestV2")
	} else {
		v1v2.V2 = &manifestV2
		logging.Get().Info().Str("module", "imagescan").Interface("image", image).Msg("get manifestV2")
	}
	if v1v2.V2 == nil {
		if err := json.Unmarshal([]byte(manifestStr), manifestV1); err == nil && manifestV1.Name != "" {
			v1v2.V1 = manifestV1
			logging.Get().Info().Str("module", "imagescan").Str("image", subtask.RegImageMeta.ImageName()).Msg("get manifestV1")
		} else {
			logging.Get().Err(err).Str("module", "imagescan").Interface("image", image).Msg("get manifestV1")
		}
	}

	if v1v2.V1 == nil && v1v2.V2 == nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("image", image).Msg("not get manifestV1 and v2")
		res.UserDockerCli = true
		return nil, fmt.Errorf("not get manifest")
		// fixme 暂时不管
		// _, err := getInspectInfo(reg.Url, reg.Username, reg.PasswordString, image.GetDockerPullImageName())
		// if err != nil {
		// 	return prepare, errors.WithMessage(err, "docker client not get manifest,and docker pull not get manifest")
		// }
	}
	lys := v1v2.GenLayerDigest()
	logging.Get().Info().Str("module", "imagescan").Strs("layers", lys).Msg("GenLayerDigest")
	// 检测所有的层是否都在缓存中，如果不在缓存中，缓存会自动pull
	for i := range lys {
		if _, _, err := client1.GetLayer(reg.Username, reg.Password, reg.Url, image.Repo, lys[i], true); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Interface("image", image).Msg("GetLayer")
			res.Errs = append(res.Errs, fmt.Errorf("can not pull layer:%s", lys[i]))
			// 保证能pull所有层级
			return nil, err
		}
		srcTarFile := fmt.Sprintf("%s%s/%s", s.CacheLayerPath, lys[i], s.TarFilename)
		layers = append(layers, types.ImageLayer{
			Digest:          lys[i],
			OriginalTarFile: srcTarFile,
		})
	}

	return layers, nil
}

func CopyFile(ctx context.Context, src string, des string) error {
	ctx, cancelFunc := context.WithTimeout(ctx, 1*time.Minute)

	defer cancelFunc()

	cmd := exec.CommandContext(ctx, "cp", "-f", src, des)

	// 设置命令的输出和错误输出
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 执行命令
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func ExtractTar(ctx context.Context, tarFile, targetDir string) error {
	ctx, cancelFunc := context.WithTimeout(ctx, 5*time.Minute)

	defer cancelFunc()
	cmd := exec.CommandContext(ctx, "tar", "-xf", tarFile, "-C", targetDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	logging.Get().Debug().Str("module", "imagescan").Strs("cmd", cmd.Args).Msg("ExtractTar")
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func CommonFilter(fi os.FileInfo) bool {
	mod := fi.Mode()
	if mod&os.ModeSymlink != 0 {
		return false
	}
	if mod&os.ModeDir != 0 {
		return false
	}
	if mod&os.ModeDevice != 0 {
		return false
	}
	if mod&os.ModeNamedPipe != 0 {
		return false
	}

	if mod&os.ModeSymlink != 0 {
		return false
	}

	if mod&os.ModeSocket != 0 {
		return false
	}

	if mod&os.ModeSocket != 0 {
		return false
	}
	if fi.Size() == 0 {
		return false
	}
	if fi.IsDir() {
		return false
	}

	return true
}

type FileFilter func(fi os.FileInfo) bool

func (s *ScanPrepare) Collect(ctx context.Context, rootDir string, filter FileFilter, prepare *types.PrepareScan) ([]string, error) {
	if prepare == nil {
		return []string{}, nil
	}
	res := make([]string, 0)
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, "etc/passwd") {
			prepare.EtcPasswdFile = path
		}

		if strings.HasSuffix(path, "etc/group") {
			prepare.EtcGroupFile = path
		}

		if filter(info) {
			res = append(res, path)
		}
		return nil
	})
	return res, err
}

func GetSimDigest(di string) string {
	split := strings.Split(di, ":")
	if len(split) >= 2 {
		return split[1]
	}
	return "tmp"
}

func GetDetDigest(di string) string {
	return fmt.Sprintf("sha25:%s", di)
}
