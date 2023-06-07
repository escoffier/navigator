package main

import (
	"path/filepath"
	"sync/atomic"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/avira"
)

func TestStart() {
	up := avira.AviraUpdate{DBPath: "/root/savapi-sdk-linux64/", IsUpdate: atomic.Int32{}}
	up.IsUpdate.Store(1)
	as := avira.NewaviraSrv(&up)
	as.StartSrv(filepath.Join(up.DBPath, avira.BinPath))
	// time.Sleep(time.Second * 10)
	// as.Stop(1)
}

func main() {
	TestStart()
	select {}
}
