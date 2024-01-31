package global

import (
	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/flag"
)

var ScannerOpts *flag2.ScannerOpts
var ScannerPodID string // scanner当前POD的ID，重新启动都会改变
var ClusterKey string
var ScannerInstance string // scanner扫描器的ID,重启后不会改变，主要用于调度仓库的同步和扫描

var VulnVer string
var SensitiveVer string
