package component

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	dockerarchive "github.com/docker/docker/pkg/archive"
	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

type WebshellScan struct {
	WebshellAddr string
	TotalFileNum int64
	MqWriter     mq.Writer
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

func (w *WebshellScan) ScanLayer(ctx context.Context, digest string, layerPath string, digestPath string, mp map[string][]scannermodel.WebshellFileInfo, IDMap scannermodel.IDMap) error {
	_, err := w.parseLayerTar(layerPath, digestPath, digest, mp, IDMap)
	if err != nil {
		return fmt.Errorf("Failed to parseLayerTar: %w", err)
	}
	return nil

}

func (w *WebshellScan) SendKafka(saveInfo scannermodel.WebshellSaveInfo) error {
	// if len(saveInfo.Data) == 0 {
	// 	logging.GetLogger().Error().Msg("WebshellScan file data is empty")
	// 	return nil
	// }

	bys, err := json.Marshal(saveInfo)
	if err != nil {
		return err
	}

	err = w.MqWriter.Write(context.Background(), scannermodel.WebshellKafkaTopic, kafka.Message{
		Key:   []byte(scannermodel.WebshellKafkaKey),
		Value: bys,
	})
	if err != nil {
		logging.GetLogger().Err(err).Str("Filename", saveInfo.Filename).Str("FileMd5", saveInfo.FileMd5).Msg("WebshellScan SendKafka")
		return err
	}
	logging.GetLogger().Debug().Int("Data", len(saveInfo.Data)).Str("FileMd5", saveInfo.FileMd5).Msg("WebshellScan SendKafka")
	return nil
}

func (w *WebshellScan) parseLayerTar(tarFileName string, digestPath string, digest string, mp map[string][]scannermodel.WebshellFileInfo, IDMap scannermodel.IDMap) (uint64, error) {
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

		if strings.Contains(header.Name, "etc/passwd") {
			fileByte, err := io.ReadAll(tarReader)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("copy from tarReader error")
			}
			w.parseUid(fileByte, IDMap.UIDMap)
			continue
		}

		if strings.Contains(header.Name, "etc/group") {
			fileByte, err := io.ReadAll(tarReader)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("copy from tarReader error")
			}
			w.parseUid(fileByte, IDMap.GIDMap)
			continue
		}

		if w.webshellFileExt(filepath.Ext(header.Name)) {
			if header.Size > scannermodel.WebshellSize {
				continue
			}
			fileByte, err := io.ReadAll(tarReader)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("copy from tarReader error")
				continue
			}
			if len(fileByte) == 0 {
				continue
			}
			fileMd5, err := w.FileMD5(bytes.NewReader(fileByte))
			if err != nil {
				logging.GetLogger().Err(err).Msgf("FileMD5")
				continue
			}
			saveInfo := scannermodel.WebshellSaveInfo{
				FileMd5: fileMd5,
				Data:    fileByte,
			}
			if err := w.SendKafka(saveInfo); err != nil {
				logging.GetLogger().Err(err).Msg("generate md5 failed")
				continue
			}

			tmpPath := filepath.Join(digestPath, fileMd5)
			tmpfs, err := os.Create(tmpPath)
			if err != nil {
				logging.GetLogger().Err(err).Msg("generate tmpFile failed")
				continue
			}

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
			tmpInfo.Md5Hash = fileMd5
			tmpInfo.ModeTime = header.ModTime.UnixMilli()
			tmpInfo.Mode = header.FileInfo().Mode().String()
			mp[fileMd5] = append(mp[fileMd5], tmpInfo)
			count++
		}
	}
	return count, nil
}

func (w *WebshellScan) parseUid(text []byte, uidMap map[int64]string) {
	byts := bytes.Split(text, []byte("\n"))
	for k := range byts {
		lines := bytes.Split(byts[k], []byte(":"))
		if len(lines) > 2 {
			uid, err := strconv.ParseInt(string(lines[2]), 10, 64)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("parse etc passwd uid error")
				continue
			}
			uidMap[uid] = string(lines[0])
		}
	}
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
