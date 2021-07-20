package main

import (
	"encoding/json"
	"io/ioutil"

	"github.com/urfave/cli/v2"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/cmd/data/tool/cleaner"
	"gitlab.com/piccolo_su/vegeta/cmd/data/tool/conf"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	util2 "gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	ClearHotOfflineStorageCmd = &cli.Command{
		Name:   "clear-hot-offline-storage-tool",
		Usage:  "clear hot offline storage data",
		Action: ClearHotOfflineStorage,
	}
)

func ClearHotOfflineStorage(*cli.Context) error {
	cleaners, err := NewOfflineStorageCleaners()
	if err != nil {
		logging.GetLogger().Error().Msgf("NewOfflineStorageCleaners fail, err:%s", err.Error())
		return err
	}

	return handleStorage(cleaners, def.GCTaskTypeHotOffline)
}

func NewOfflineStorageCleaners() (cleaners []def.Cleaner, err error) {
	confBytes, err := ioutil.ReadFile(util2.GetEnvWithDefault(env.ConfPath, env.DefaultConfPath))
	if err != nil {
		logging.GetLogger().Error().Msgf("load conf file fail, err:%s", err.Error())
		return nil, err
	}

	var offlineConf *conf.OfflineConf
	err = json.Unmarshal(confBytes, &offlineConf)
	if err != nil {
		logging.GetLogger().Error().Msgf("parse conf fail, err:%s", err.Error())
		return nil, err
	}

	logging.GetLogger().Info().Msgf("conf:%+v", offlineConf)

	esCleaner, err := cleaner.NewESCleaner(
		util2.GetEnvWithDefault(env.ElasticURL, env.DefaultElasticURL), offlineConf.ESIndexPrefixes)
	if err != nil {
		return nil, err
	}

	return []def.Cleaner{esCleaner}, nil
}
