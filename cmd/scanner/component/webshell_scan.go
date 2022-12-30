package component

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	dockerarchive "github.com/docker/docker/pkg/archive"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

type WebshellScan struct {
	WebshellAddr string
	TotalFileNum int64
}

func (w *WebshellScan) FileMD5(tar io.Reader) (string, error) {
	hash := md5.New()
	_, _ = io.Copy(hash, tar)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (w *WebshellScan) PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

func (w *WebshellScan) ScanLayer(ctx context.Context, digest string, layerPath string, digestPath string, mp map[string][]scannermodel.WebshellFileInfo) error {
	_, err := w.parseLayerTar(layerPath, digestPath, digest, mp)
	if err != nil {
		return fmt.Errorf("Failed to parseLayerTar: %w", err)
	}
	return nil

}

func (w *WebshellScan) parseLayerTar(tarFileName string, digestPath string, digest string, mp map[string][]scannermodel.WebshellFileInfo) (uint64, error) {
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
		if w.webshellFileExt(filepath.Ext(header.Name)) {
			if header.Size > scannermodel.WebshellSize {
				continue
			}
			fileByte, err := io.ReadAll(tarReader)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("copy from tarReader error")
			}

			fileMd5, err := w.FileMD5(bytes.NewReader(fileByte))
			if err != nil {
				logging.GetLogger().Err(err).Msg("generate md5 failed")
				continue
			}
			tmpPath := filepath.Join(digestPath, fileMd5)
			tmpfs, err := os.Create(tmpPath)
			if err != nil {
				logging.GetLogger().Err(err).Msg("generate tmpFile failed")
				continue
			}
			//logging.GetLogger().Info().Msgf("name :%v,size:%v", header.Name, header.Size)
			_, err = io.Copy(tmpfs, bytes.NewReader(fileByte))
			if err != nil {
				logging.GetLogger().Err(err).Msg("copy tmpFile failed")
				continue
			}
			tmpfs.Close()
			tmpInfo := scannermodel.WebshellFileInfo{}
			tmpInfo.FilePath = tmpPath
			tmpInfo.FileName = header.Name
			tmpInfo.Size = header.Size
			tmpInfo.LayerDigest = digest
			tmpInfo.ModeTime = header.ModTime.UnixMilli()
			tmpInfo.Mode = header.FileInfo().Mode().String()
			mp[fileMd5] = append(mp[fileMd5], tmpInfo)
			count++
		}
	}
	return count, nil
}

// webshell文件后缀列表
var extSlice = []string{
	".php", ".php5", ".php4", ".asp", ".aspx", ".asmx", ".ashx", ".jsp",
	".jspa", ".jspx", ".jspf", ".cer", ".htaccess",
}

// 判断webshell文件后缀是否是给定的后缀
func (w *WebshellScan) webshellFileExt(ext string) bool {

	for i := range extSlice {
		if extSlice[i] == ext {
			return true
		}
	}

	return false
}
