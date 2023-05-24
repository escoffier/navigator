package main

import (
	"flag"
	"os"

	"gitlab.com/security-rd/go-pkg/logging"
	"scm.tensorsecurity.cn/tensorsecurity-rd/falcosider/manager"
)

func main() {
	outputPath := flag.String("output",
		"/var/run/holmes-engine/rules/",
		"rules file directory")

	err := manager.SetTmpRuleFilesFromLocalCache(*outputPath)
	if err != nil {
		logging.Get().Err(err).Msg("set file from local cache error")
		os.Exit(1)
	}
}
