package main

import (
	"os"

	"github.com/urfave/cli/v2"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func main() {
	var app = cli.App{
		Name:  "data-tool",
		Usage: "data management tool",
		Commands: []*cli.Command{
			DumpHotLogicStorageCmd,
			ClearHotOfflineStorageCmd,
			ClearColdStorageCmd,
		},
		Version: "0.0.1",
	}

	var err = app.Run(os.Args)
	if err != nil {
		logging.GetLogger().Fatal().Msgf("run fail, err:%s", err.Error())
	}
}
