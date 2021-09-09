//go:generate swag init

package main

import (
	"gitlab.com/piccolo_su/vegeta/cmd/console/cmd"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	_ "go.uber.org/automaxprocs"
)

// @title Vegeta API·
// @version 1.0
// @description This is the Vegeta central server - Console

// @BasePath /
func main() {
	util.InitPprofMontitor()
	cmd.Execute()
}
