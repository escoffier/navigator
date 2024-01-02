package main

import (
	"math/rand"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/node-image/cmd"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	_ "gitlab.com/piccolo_su/vegeta/cmd/node-image/services/assets"
	_ "gitlab.com/piccolo_su/vegeta/cmd/node-image/services/avira"
	_ "gitlab.com/piccolo_su/vegeta/cmd/node-image/services/cache"
	_ "gitlab.com/piccolo_su/vegeta/cmd/node-image/services/stream"
	_ "gitlab.com/piccolo_su/vegeta/cmd/node-image/services/tasks"
)

func main() {
	util.InitPprofMontitor()
	rand.Seed(time.Now().UnixNano())
	rootCmd := cmd.NewRootCmd()
	_ = rootCmd.Execute()
}
