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
	"time"

	"github.com/docker/distribution/manifest/schema2"
	dockerarchive "github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/pools"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imageCache "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

func createTarFile(destDir string, header *tar.Header, red io.Reader) error {
	target := filepath.Join(destDir, header.Name)
	switch header.Typeflag {
	case tar.TypeDir:
		if err := os.MkdirAll(target, os.ModePerm); err != nil {
			return err
		}
	case tar.TypeReg:
		if err := scannerUtils.SaveFileFromTarReader(red, target); err != nil {
			return err
		}
	}
	return nil
}

// 使用untar 命令
func (s *RegImagePrepare) extractTarUseTar(ctx context.Context, tarFile, targetDir string) error {

	_ = os.RemoveAll(targetDir)
	_ = os.MkdirAll(targetDir, os.ModePerm)

	ctx, cancelFunc := context.WithTimeout(ctx, 5*time.Minute)

	defer cancelFunc()
	cmd := exec.CommandContext(ctx, "tar", "-xf", tarFile, "-C", targetDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	s.Log.Debug().Strs("cmd", cmd.Args).Msg("extractDockerTar1")
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

// 使用 docker 项目提供的解方法
func (s *RegImagePrepare) extractDockerTar2(tarFile, destDir string) error {
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
		s.Log.Err(err).Str("tarFile", tarFile).Str("destDir", destDir).Msg("extractDockerTar1")
		return err
	}
	defer func() { _ = decompressStreamReader.Close() }()
	// 直接调用 docker 提供的方法
	if _, err := dockerarchive.UnpackLayer(destDir, decompressStreamReader, nil); err != nil {
		s.Log.Err(err).Str("tarFile", tarFile).Str("destDir", destDir).Msg("extractDockerTar1")
		return err
	}
	s.Log.Debug().Str("tarFile", tarFile).Str("destDir", destDir).Msg("extractDockerTar1 success")
	return nil
}

// 直接读取 tar 包
func (s *RegImagePrepare) extractDockerTar1(tarFile, destDir string) error {
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
		s.Log.Err(err).Str("tarFile", tarFile).Str("destDir", destDir).Msg("extractDockerTar1")
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
			s.Log.Err(err).Str("tarFile", tarFile).Str("destDir", destDir).Msg("extractDockerTar1 tarReader")
			return err
		}

		target := filepath.Join(destDir, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.ModePerm); err != nil {
				s.Log.Err(err).Str("tarFile", tarFile).Str("target", target).Msg("extractDockerTar1 MkdirAll")
				return err
			}
		case tar.TypeReg:
			if err := scannerUtils.SaveFileFromTarReader(tarReader, target); err != nil {
				s.Log.Err(err).Str("tarFile", tarFile).Str("target", target).Msg("extractDockerTar1 writeFile")
				continue
			}
		}
	}
	s.Log.Debug().Str("tarFile", tarFile).Str("destDir", destDir).Msg("extractDockerTar1 success")
	return nil
}

// 使用BufioReader32KPool,加快速度
func (s *RegImagePrepare) extractDockerTar3(tarFile, destDir string) error {
	_ = os.RemoveAll(destDir)
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
		return err
	}

	defer func() { _ = decompressStreamReader.Close() }()

	tr := tar.NewReader(decompressStreamReader)
	trBuf := pools.BufioReader32KPool.Get(tr)
	defer pools.BufioReader32KPool.Put(trBuf)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			// end of tar archive
			break
		}
		if err != nil {
			return err
		}

		trBuf.Reset(tr)
		srcData := io.Reader(trBuf)

		if err := createTarFile(destDir, hdr, srcData); err != nil {
			return err
		}
	}
	s.Log.Debug().Str("tarFile", tarFile).Str("destDir", destDir).Msg("extractDockerTar1 success")
	return nil
}

func (s *RegImagePrepare) logScanEnd(start int64, pre *imagesecTypes.PrepareScan) {
	s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).Str(consts.ScanJobLogName, "Prepare").
		Int64("cost", time.Now().Unix()-start).Msg("scan job end")
}

func (s *RegImagePrepare) logScanStart(pre *imagesecTypes.PrepareScan) {
	s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).Str(consts.ScanJobLogName, "Prepare").Msg("scan job start")
}

// 使用cp命令拷贝文件
func (s *RegImagePrepare) copyFile(ctx context.Context, src string, des string) error {
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

func (s *RegImagePrepare) genRootDir(ctx context.Context, subtask imagesecTypes.ScanSubTask) (string, error) {
	// 每次任务的 ID 是不一样的，且只有失败的任务才可以重试,所以不会有误删除情况
	dir := filepath.Join(s.ScanCachePath, fmt.Sprintf("%d", subtask.SubTaskID))
	s.Log.Debug().Str("taskRootPath", dir).Msg("genRootDir")
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return "", err
	}
	return dir, nil
}

func (s *RegImagePrepare) getManifest(ctx context.Context, subtask imagesecTypes.ScanSubTask) (imagesecTypes.ManifestV2AndV1, error) {
	v1v2 := imagesecTypes.ManifestV2AndV1{}
	client, err := imageCache.NewLocalLayerManageClientT("/manifest")
	if err != nil {
		s.Log.Err(err).Msg("new manifest client error")
		return v1v2, err
	}

	manifestV1 := new(model.ManifestV1)

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
		return v1v2, fmt.Errorf("not get manifest")
		// fixme 暂时不管
		// _, err := getInspectInfo(reg.Url, reg.Username, reg.PasswordString, image.GetDockerPullImageName())
		// if err != nil {
		// 	return prepare, errors.WithMessage(err, "docker client not get manifest,and docker pull not get manifest")
		// }
	}
	if v1v2.V2 == nil {
		return v1v2, fmt.Errorf("not get manifest v2")
	}
	// 对于 V1只能使用 docker pull ，暂时先不考虑
	v1v2.ImageDigest = scannerUtils.ManifestV2Digest(v1v2.V2)

	return v1v2, nil
}

func (s *RegImagePrepare) findNeedPrepareLayer(ctx context.Context, prep *imagesecTypes.PrepareScan) {

	if !prep.Subtask.VulnCache.In(prep.ImageManifest.ImageDigest) {
		s.Log.Debug().Str("ImageDigest", prep.ImageManifest.ImageDigest).Msg("vuln not cached")
		for i := range prep.Layers {
			prep.Layers[i].NeedPull = true
		}
	}
	for _, ly := range prep.Layers {
		pull, ext := ly.NeedPull, ly.NeedExtract
		if !prep.Subtask.SensitiveCache.In(ly.Digest) {
			pull = true
		}
		if !prep.Subtask.LicenseCache.In(ly.Digest) {
			pull = true
		}
		if prep.Subtask.DeepScan && !prep.Subtask.MalwareCache.In(ly.Digest) {
			pull = true
			ext = true
		}
		if prep.Subtask.DeepScan && !prep.Subtask.WebshellCache.In(ly.Digest) {
			pull = true
			ext = true
		}
		prep.Layers[ly.Digest].NeedPull = pull
		prep.Layers[ly.Digest].NeedExtract = ext
	}
	return
}

// 要特别注意
// 因为第一个不是镜像层文件,是镜像inspect 的信息
// 糟糕的设计，因为这个设计，后面如果和节点镜像整合时会有麻烦
// 拉取镜像元信息的数据
func (s *RegImagePrepare) pullInspectLayer(ctx context.Context, prep *imagesecTypes.PrepareScan, ly string) error {
	client1, err := imageCache.NewLocalLayerManageClientT("/layer")
	if err != nil {
		s.Log.Err(err).Msg("new layer client error")
		return err
	}
	reg, image := prep.Subtask.RegInfo, prep.Subtask.RegImageMeta
	if _, _, err := client1.GetLayer(reg.Username, reg.Password, reg.Url, image.Repo, ly, true); err != nil {
		s.Log.Err(err).Str("subtask", prep.Subtask.LogStr()).Str("layer", ly).Msg("GetLayer")
		return err
	}
	s.Log.Debug().Str("subtask", prep.Subtask.LogStr()).Str("inspectDigest", ly).Msg("pullInspectLayer")
	return nil
}
