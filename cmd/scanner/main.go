package main

import (
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// @title Vegeta API·
// @version 1.0
// @description This is the Vegeta central server - Scanner

// @BasePath /

func main() {
	_ = util.InitPprofMontitor()

	cmd.Execute()
}
