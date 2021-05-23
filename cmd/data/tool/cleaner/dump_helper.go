package cleaner

import (
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/data/tool/conf"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"io"
	"os"
	"path"
	"time"
)

const (
	dumpTimeLayout = "2006-01-02T15:04:05.000"
)

func initDumpInfo(item *conf.DumpItem, timeFilter time.Time) (string, string, error) {
	if err := os.MkdirAll(item.DataDir, os.ModePerm); err != nil {
		return "", "", err
	}

	targetPath := path.Join(item.DataDir, timeFilter.Format(dumpTimeLayout))
	tmpPath := path.Join(item.DataDir, fmt.Sprintf("%s-tmp", item.Name))

	return targetPath, tmpPath, nil
}

func clearDumpInfo(targetFile *os.File, tmpPath string) {
	if targetFile != nil {
		if _err := targetFile.Close(); _err != nil {
			logging.GetLogger().Error().Msgf("close file fail, err:%s", _err.Error())
		}
	}

	if _, _err := os.Stat(tmpPath); _err == nil {
		if _err = os.Remove(tmpPath); _err != nil {
			logging.GetLogger().Error().Msgf("remove tmp file fail, err:%s", _err.Error())
		}
	}
}

func mergeDumpFile(tmpPath string, targetFile *os.File) error {
	tmpFile, err := os.Open(tmpPath)
	if err != nil {
		return err
	}

	defer func() {
		if _err := tmpFile.Close(); _err != nil {
			logging.GetLogger().Error().Msgf("close file fail, err:%s", err.Error())
		}
	}()
	_, err = io.Copy(targetFile, tmpFile)
	return err
}

func checkFileExists(file string) (bool, error) {
	_, err := os.Stat(file)
	if err == nil {
		return true, nil
	}

	if os.IsNotExist(err) {
		return false, nil
	}

	return false, err
}
