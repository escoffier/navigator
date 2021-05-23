package cleaner

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type ColdCleaner struct {
	rootPath string
}

func NewColdCleaner(rootPath string) *ColdCleaner {
	return &ColdCleaner{rootPath: rootPath}
}

func (c ColdCleaner) Clean(_ context.Context, daysOffset int) error {
	timeFilter := time.Now().Add(-time.Hour * 24 * time.Duration(daysOffset))
	return filepath.Walk(c.rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logging.GetLogger().Warn().Msgf("walkDir error:%s, path:%s", err.Error(), path)
			return nil
		}

		if info.IsDir() {
			return nil
		}

		t, parseErr := time.ParseInLocation(dumpTimeLayout, info.Name(), time.Local)
		if parseErr != nil {
			logging.GetLogger().Info().Msgf("ignore file:%s", path)
			return nil
		}

		if t.Before(timeFilter) {
			removeErr := os.Remove(path)
			if removeErr != nil {
				logging.GetLogger().Error().Msgf("remove file:%s fail, err:%s", path, removeErr.Error())
			} else {
				logging.GetLogger().Info().Msgf("remove file:%s successfully", path)
			}
		}

		return nil
	})
}
