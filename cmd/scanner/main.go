package main

import (
	"math/rand"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	_ "go.uber.org/automaxprocs"
)

// @title Vegeta API·
// @version 1.0
// @description This is the Vegeta central server - Scanner

// @BasePath /

func main() {
	util.InitPprofMontitor()
	rand.Seed(time.Now().UnixNano())

	cmd.Execute()
}

