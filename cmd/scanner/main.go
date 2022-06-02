package main

import (
	"math/rand"
	"time"

	_ "go.uber.org/automaxprocs"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/dequeue"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/gen-whitelist"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/pull-image"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/save-result"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/scan"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/aliacr"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/aliacr-ee"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/docker"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/harborv1"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/harborv2"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/hwswr"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/jfrog"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnnvd"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnvd"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/trivy"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/api"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/cronjob"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-sync"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/malicious"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/scanner-vuln"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/task-check"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/task-policy"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/trivy-srv"
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
