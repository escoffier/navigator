package global

import (
	"sync"

	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/flag"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

var TaskWg *sync.WaitGroup       // wait for all task processed before ti db update
var TiDbUpdateWg *sync.WaitGroup // stop processing requests during ti db update
var ScannerOpts *flag2.ScannerOpts
var ScannerPodID string // scanner当前POD的ID，重新启动都会改变
var ClusterKey string
var ClusterName string
var ScannerInstance string // scanner扫描器的ID,重启后不会改变，主要用于调度仓库的同步和扫描
var VulnDBVersion *scannermodel.ScannerDBVersion
var SubtaskParallel int
var PVCPath string

func init() {
	TaskWg = &sync.WaitGroup{}
	TiDbUpdateWg = &sync.WaitGroup{}
}
