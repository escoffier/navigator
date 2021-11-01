package component

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	dockerarchive "github.com/docker/docker/pkg/archive"
	"github.com/rs/zerolog"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type MaliciousScan struct {
}

func (m *MaliciousScan) ScanLayer(ctx context.Context, digest string, layerPath string) ([]model.VirusInfo, error) {
	digestNum := strings.Split(digest, ":")[1]
	timeUnix := time.Now().Unix()
	timeUnixStr := strconv.FormatInt(timeUnix, 10)
	tmpDir := filepath.Join("/tmpscan/", digestNum+timeUnixStr)
	err := os.MkdirAll(tmpDir, 0777)
	if err != nil {
		return []model.VirusInfo{}, err
		//错误处理
	}
	defer os.RemoveAll(tmpDir)
	fileCount, err := m.parseLayerTar(layerPath, tmpDir)
	if err != nil {
		return []model.VirusInfo{}, fmt.Errorf("Failed to parseLayerTar: %w", err)
	}

	// logging.GetLogger().Info().Msgf("fileCount :%v ", fileCount)

	if fileCount == 0 {
		return []model.VirusInfo{}, nil

	}

	virusInfos, err := m.clamavScan(ctx, tmpDir, digestNum)
	if err != nil {
		return []model.VirusInfo{}, fmt.Errorf("Clamscan Error %w", err)
	}

	if len(virusInfos) != 0 {
		zerolog.Ctx(ctx).Info().Str("Filename:", virusInfos[0].FileName).Str("Virusname:", virusInfos[0].VirusName).Str("FilePath", virusInfos[0].FilePath).Msg("The digest scan result")
	}

	return virusInfos, nil
}

func (m *MaliciousScan) clamavScan(ctx context.Context, scanPath string, digestNum string) ([]model.VirusInfo, error) {

	clamLogPath := scanPath + ".log"
	cmd := exec.Command("/usr/bin/clamdscan", "--quiet", "-m", scanPath, "-l", clamLogPath)
	// logging.GetLogger().Info().Str("scanPath", scanPath).Str("clamLogPath", clamLogPath).Msg("ScanPath")
	defer os.Remove(clamLogPath)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()

	if err != nil {
		// 扫描到病毒时err返回值为1,所以不能退出,错误时ParseSummrylogs读不到日志文件，会返回空集。
		errString := fmt.Sprintf("%s", err)
		if strings.Compare("exit status 1", errString) != 0 {
			zerolog.Ctx(ctx).Info().Err(err).Str("Out:", out.String()).Str("Stderr:", stderr.String()).Str("ScanPath:", scanPath).Msg("Cla ERROR")
			return []model.VirusInfo{}, fmt.Errorf("ClamScan Error %w", err)
		}
	}

	zerolog.Ctx(ctx).Info().Msg("Clamscan ok")
	VirusInfos := m.ParseSummrylogs(clamLogPath, scanPath)
	return VirusInfos, nil
}

func (m *MaliciousScan) ParseSummrylogs(logPath string, scanPath string) []model.VirusInfo {
	replaceString := scanPath[0 : len(scanPath)-1]
	ClamAvVirus := []model.VirusInfo{}
	reader, err := ioutil.ReadFile(logPath)
	if err != nil {
		return []model.VirusInfo{}
	}
	str := (*string)(unsafe.Pointer(&reader))
	strSplit := strings.Split(*str, "\n")
	for _, val := range strSplit {
		tmp := strings.Index(val, "FOUND")
		if tmp != -1 {
			tmpResult := strings.Split(val[0:tmp-1], ":")
			if len(tmpResult) < 2 {
				continue
			}
			fileName := tmpResult[0][strings.LastIndex(tmpResult[0], "/")+1:]
			ClamAvVirus = append(ClamAvVirus, model.VirusInfo{FileName: fileName, FilePath: strings.Replace(tmpResult[0], replaceString, "", 1), VirusName: tmpResult[1]})
		}
	}
	return ClamAvVirus
}

func (m *MaliciousScan) parseLayerTar(tarFileName string, dst string) (uint64, error) {
	tarFile, err := os.Open(tarFileName)
	if err != nil {
		return 0, fmt.Errorf("Failed to advance tarReader: %w", err)
	}
	defer func() { _ = tarFile.Close() }() // close the file

	decompressStreamReader, err := dockerarchive.DecompressStream(tarFile)
	if err != nil {
		return 0, fmt.Errorf("Failed to DecompressStream: %w", err)
	}

	defer func() { _ = decompressStreamReader.Close() }() // close the decompressStreamReader

	tarReader := tar.NewReader(decompressStreamReader)
	var count uint64 = 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return count, fmt.Errorf("Failed to advance tarReader: %w", err)
		}

		// 检查类型，过滤文件夹、软链接和硬链接
		switch header.Typeflag {
		case tar.TypeDir, tar.TypeLink, tar.TypeSymlink:
			continue
		}
		// fmt.Println(header.Name)
		perm := header.FileInfo().Mode().Perm()
		f := perm & os.FileMode(73)

		// 判断文件是否是可执行文件或者webshell后缀的文件
		if uint32(f) == uint32(73) {
			// 这里这样写防止ioutil.ReadAll读取所有的内容
			file, _ := m.createFile(filepath.Join(dst, header.Name))
			_, err := io.Copy(file, tarReader)
			if err != nil {
				logging.GetLogger().Error().Msgf("virusScan io.Copy error %v", err)
			}
			err = os.Chmod(filepath.Join(dst, header.Name), 0666)
			if err != nil {
				logging.GetLogger().Error().Msgf("virusScan os.Chmod error %v", err)
			}
			count++
		}
	}
	return count, nil
}

func (m *MaliciousScan) createFile(name string) (*os.File, error) {
	err := os.MkdirAll(string([]rune(name)[0:strings.LastIndex(name, "/")]), 0755)
	if err != nil {
		return nil, err
	}
	return os.Create(name)
}
