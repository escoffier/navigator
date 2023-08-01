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
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	dockerarchive "github.com/docker/docker/pkg/archive"
	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

type LicenseScan struct {
	licenseFilenameRegExpMap map[*regexp.Regexp]*model.LicenseInfo
	licenseFilenameRegExp    *regexp.Regexp
	MqWriter                 mq.Writer
}

func (l *LicenseScan) ScanLayer(ctx context.Context, layerPath string) ([]model.LicenseInfo, error) {
	return l.parseLayerTar(layerPath)
}

func (l *LicenseScan) parseLayerTar(tarFileName string) ([]model.LicenseInfo, error) {
	tarFile, err := os.Open(tarFileName)
	if err != nil {
		return nil, fmt.Errorf("Failed to advance tarReader: %w", err)
	}
	defer func() { _ = tarFile.Close() }() // close the file

	decompressStreamReader, err := dockerarchive.DecompressStream(tarFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to DecompressStream: %w", err)
	}

	defer func() { _ = decompressStreamReader.Close() }() // close the decompressStreamReader

	tarReader := tar.NewReader(decompressStreamReader)

	res := make([]model.LicenseInfo, 0)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("Failed to advance tarReader: %w", err)
		}

		// 检查类型，过滤文件夹、软链接和硬链接
		switch header.Typeflag {
		case tar.TypeDir, tar.TypeLink, tar.TypeSymlink:
			continue
		}

		if strings.Contains(strings.ToUpper(header.Name), "LICENSE") {
			fileByte, err := io.ReadAll(tarReader)
			if err != nil {
				logging.Get().Err(err).Msgf("copy from tarReader error")
				continue
			}
			if len(fileByte) == 0 {
				continue
			}
			li := GetLicenseName(fileByte)
			if li == "" {
				continue
			}
			hash := md5.New()
			_, _ = io.Copy(hash, bytes.NewBuffer(fileByte))
			fileMd5 := hex.EncodeToString(hash.Sum(nil))

			lic := model.LicenseInfo{Name: li, Filename: header.Name, MD5: fileMd5, Data: fileByte}

			_ = l.SendKafka(lic)

			res = append(res, lic)
		}
	}
	return res, nil
}

func (l *LicenseScan) Init() {
	licenseDescription := []model.LicenseInfo{}

	if err := l.readJSONFile("/configs/scanner/license.json", &licenseDescription); err != nil {
		return
	}
	var licenseFilenameRegExpStrList []string
	for _, item := range licenseDescription {
		licenseFilenameRegExpStrList = append(licenseFilenameRegExpStrList, item.Value)
	}
	licenseFilenameRegExp := regexp.MustCompile(strings.Join(licenseFilenameRegExpStrList, "|"))
	l.licenseFilenameRegExp = licenseFilenameRegExp
}

func (l *LicenseScan) Find(content string) (model.LicenseInfo, bool) {

	res := l.licenseFilenameRegExp.FindString(content)
	if res != "" {
		for re, v := range l.licenseFilenameRegExpMap {
			tmp := re.FindString(res)
			if tmp != "" {
				return *v, true
			}
		}
	}
	return model.LicenseInfo{}, false
}

func (l *LicenseScan) readJSONFile(path string, fieldPtr interface{}) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("Failed to open file %s: %w", path, err)
	}
	defer f.Close()

	byteValue, _ := ioutil.ReadAll(f)
	err = json.Unmarshal(byteValue, fieldPtr)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal file %s: %w", path, err)
	}
	return nil
}

func GetLicenseName(data []byte) string {
	con := string(data)

	if strings.Contains(con, "New BSD License") {
		return "BSD 3-Clause"
	}

	if strings.Contains(con, "GNU GENERAL PUBLIC LICENSE") {
		return "GPL"
	}

	if strings.Contains(con, "BSD 2-Clause") {
		return "BSD 2-Clause"
	}

	if strings.Contains(con, "MIT") {
		return "MIT"
	}

	if strings.Contains(con, "Mozilla Public License Version") {
		return "MPT"
	}

	if strings.Contains(con, "Apache License") {
		return "Apache License"
	}

	if strings.Contains(con, "Permission to use, copy, modify") {
		return "ISC"
	}
	return ""
}

func (l *LicenseScan) SendKafka(saveInfo model.LicenseInfo) error {
	up := scannermodel.WebshellSaveInfo{
		FileMd5:  saveInfo.MD5,
		Data:     saveInfo.Data,
		Filename: saveInfo.Filename,
	}

	// if len(up.Data) == 0 {
	// 	logging.Get().Error().Msg("license file data is empty")
	// 	return nil
	// }
	bys, err := json.Marshal(up)
	if err != nil {
		return err
	}

	err = l.MqWriter.Write(context.Background(), scannermodel.WebshellKafkaTopic, kafka.Message{
		Key:   []byte(scannermodel.WebshellKafkaKey),
		Value: bys,
	})
	if err != nil {
		logging.Get().Err(err).Str("filename", saveInfo.Filename).Str("FileMd5", saveInfo.MD5).Msg("license SendKafka")
		return err
	}
	logging.Get().Debug().Int("Data", len(saveInfo.Data)).Str("FileMd5", saveInfo.MD5).Msg("license SendKafka")
	return nil
}
