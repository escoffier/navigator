package component

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	dockerarchive "github.com/docker/docker/pkg/archive"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type LicenseScan struct {
	licenseFilenameRegExpMap map[*regexp.Regexp]*model.LicenseInfo
	licenseFilenameRegExp    *regexp.Regexp
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

	var res []model.LicenseInfo

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
		fileName := header.Name
		lastIndex := strings.LastIndex(header.Name, "/")
		if lastIndex != -1 {
			fileName = header.Name[lastIndex+1:]
		}
		if strings.Contains(strings.ToLower(fileName), "license") {
			content, err := ioutil.ReadAll(tarReader)
			if err != nil {
				continue
			}
			strContent := string(content)
			if len(content) == 0 {
				continue
			}
			tmpLincense, ok := l.Find(strContent)
			logging.GetLogger().Info().Msgf("headerName:%v tmpLicense:%v", fileName, tmpLincense)
			if ok {
				res = append(res, tmpLincense)
			}
		}
	}
	return res, nil
}

func (l *LicenseScan) Init() {
	licenseFilenameRegExpMap := make(map[*regexp.Regexp]*model.LicenseInfo)
	licenseDescription := []model.LicenseInfo{}

	if err := l.readJSONFile("/configs/scanner/license.json", &licenseDescription); err != nil {
		return
	}
	var licenseFilenameRegExpStrList []string
	for i, item := range licenseDescription {

		licenseFilenameRegExpMap[regexp.MustCompile(item.Value)] = &licenseDescription[i]
		licenseFilenameRegExpStrList = append(licenseFilenameRegExpStrList, item.Value)

	}
	licenseFilenameRegExp := regexp.MustCompile(strings.Join(licenseFilenameRegExpStrList, "|"))
	l.licenseFilenameRegExpMap = licenseFilenameRegExpMap
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
