package main

import (
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/cmd"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"math/rand"
	"time"
)

func main() {
	util.InitPprofMontitor()
	rand.Seed(time.Now().UnixNano())
	rootCmd := cmd.NewRootCmd()
	_ = rootCmd.Execute()
}
