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
	DumpHotLogicStorageCmd = &cli.Command{
		Name:   "hot-logic-storage-tool",
		Usage:  "hot logic storage tool",
		Action: DumpHotLogicStorage,
	}
)

func DumpHotLogicStorage(*cli.Context) error {
	cleaners, err := NewLogicStorageCleaners()
	if err != nil {
		logging.GetLogger().Error().Msgf("NewLogicStorageCleaners fail, err:%s", err)
		return err
	}

	return handleStorage(cleaners, def.GCTaskTypeHotLogic)
}

func NewLogicStorageCleaners() (cleaners []def.Cleaner, err error) {
	confBytes, err := ioutil.ReadFile(util2.GetEnvWithDefault(env.ConfPath, env.DefaultConfPath))
	if err != nil {
		logging.GetLogger().Error().Msgf("load conf file fail, err:%s", err.Error())
		return nil, err
	}

	var dumpConf *conf.DumpLogicConf
	err = json.Unmarshal(confBytes, &dumpConf)
	if err != nil {
		logging.GetLogger().Error().Msgf("parse conf fail, err:%s", err.Error())
		return nil, err
	}

	logging.GetLogger().Info().Msgf("conf:%+v", dumpConf)

	mongoClient, err := NewMongoClientFromEnv()
	if err != nil {
		logging.GetLogger().Error().Msgf("new mongo client fail:%s", err.Error())
		return nil, err
	}

	pgClient, err := NewPostgresClientFromEnv()
	if err != nil {
		logging.GetLogger().Error().Msgf("new postgres client fail:%s", err.Error())
		return nil, err
	}

	return []def.Cleaner{
		cleaner.NewPostgresCleaner(pgClient, dumpConf.PGTables),
		cleaner.NewMongoCleaner(mongoClient, dumpConf.MongoUnifiedConf),
	}, nil
}
