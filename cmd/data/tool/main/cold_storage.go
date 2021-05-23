package main

import (
	"github.com/urfave/cli/v2"
	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/cmd/data/tool/cleaner"
)

var ClearColdStorageCmd = &cli.Command{
	Name:   "clear-cold-storage-tool",
	Usage:  "clear cold storage tool",
	Action: ClearColdStorage,
}

func ClearColdStorage(*cli.Context) error {
	return handleStorage([]def.Cleaner{
		cleaner.NewColdCleaner(env.GetEnvWithDefault(env.AuditPath, env.DefaultAuditPath))}, def.GCTaskTypeCold)
}
