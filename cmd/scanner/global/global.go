package global

import (
	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/flag"
	"sync"
)

var TaskWg *sync.WaitGroup       // wait for all task processed before ti db update
var TiDbUpdateWg *sync.WaitGroup // stop processing requests during ti db update
var ScannerOpts *flag2.ScannerOpts
var ScannerId string

func init() {
	TaskWg = &sync.WaitGroup{}
	TiDbUpdateWg = &sync.WaitGroup{}
}
