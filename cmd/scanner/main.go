package main

import (
	"math/rand"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd"

	_ "go.uber.org/automaxprocs"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/api"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/datamigrate"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/db-manage"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/detect"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/imagescan"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/kafka-report"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/malicious"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/registry"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/scanner-vuln"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/scanner-webshell"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/stream2"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/subscanner-log"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/trivy-srv"

	// for test
	// _ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/sync-config"
	_ "gitlab.com/piccolo_su/vegeta/pkg/api/apikey"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
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
