package main

import (
	"math/rand"
	"time"

	_ "go.uber.org/automaxprocs"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/api"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/ci"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/detect"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/imagescan"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/kafkaReport"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/registry"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/stream2"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	// for test
	// _ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/db-manage"
	// _ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/sync-config"
	_ "gitlab.com/piccolo_su/vegeta/pkg/api/apikey"
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
