package prepare

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	dockerarchive "github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/pools"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
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
func (s *RegImagePrepare) ExtractTar(ctx context.Context, tarFile, targetDir string) error {

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

// 使用cp命令拷贝文件
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
