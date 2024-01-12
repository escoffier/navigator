package hm

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type ScanHM struct {
	BinCnt      int64
	EnginBack   []*EnginMeta
	WG          sync.Locker // 主要用于获取引擎
	HmRootPath  string      // /opt/webshell/hm
	ScanTimeout int64       // 单位：秒
	Log         *scannerUtils.LogEvent
}

type EnginMeta struct {
	Using       bool // 是否在使用中
	EnginNO     int64
	HmRootPath  string // /opt/webshell/hm
	BinFilename string // hm 的二制制执行文件
	DbFilename  string // hm 扫描后会把结果果保存在当前目录的data.db文件中,这是一个sqlite文件
	CsvFilename string // hm 扫描后会把结果果保存在当前目录的result.csv文件中,这是一个csv文件
	Log         *scannerUtils.LogEvent
}

type SingleHMSrv struct {
	ScanHM *ScanHM
	WG     sync.Locker
}

// 这样才保险
func init() {
	singleHmMeta = &SingleHMSrv{
		ScanHM: nil,
		WG:     &sync.Mutex{},
	}
}

var singleHmMeta *SingleHMSrv

// 单例
func NewScanHM(opts ...Option) (*ScanHM, error) {
	singleHmMeta.WG.Lock()
	defer singleHmMeta.WG.Unlock()

	if singleHmMeta.ScanHM != nil {
		return singleHmMeta.ScanHM, nil
	}
	s := &ScanHM{
		HmRootPath:  "/opt/webshell/hm",
		ScanTimeout: 10 * 60,
		WG:          &sync.Mutex{},
		BinCnt:      consts.DefaultHmEnginCnt,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("ScanHM"),
			scannerUtils.WithModule(consts.ModuleImageScan),
		),
	}
	cnt, err := strconv.Atoi(os.Getenv("HM_ENGIN_CNT"))
	if err == nil && cnt > 0 {
		s.BinCnt = int64(cnt)
	}

	for i := range opts {
		opts[i](s)
	}

	if err := s.createHmBack(context.Background(), int(s.BinCnt)); err != nil {
		return nil, err
	}

	singleHmMeta.ScanHM = s

	return singleHmMeta.ScanHM, nil
}

func (s *ScanHM) ImageScan(ctx context.Context, pre *imagesecTypes.PrepareScan) []imagesecTypes.ScanJobResult {
	start := time.Now().Unix()
	s.logScanStart(pre)
	defer s.logScanEnd(start, pre)

	result := make([]imagesecTypes.ScanJobResult, 0)
	out := make(chan imagesecTypes.ScanJobResult)
	defer close(out)

	for i := range pre.Layers {
		ly := pre.Layers[i]
		go func(tx context.Context, ly *imagesecTypes.ImageLayer, prep *imagesecTypes.PrepareScan, out chan imagesecTypes.ScanJobResult) {
			s.scanJob(ctx, ly, prep, out)
		}(ctx, ly, pre, out)
	}

	for i := 0; i < len(pre.Layers); i++ {
		res := <-out
		result = append(result, res)
	}

	uidMap, gidMap, _ := s.getPasswdAndGroupFromFile(ctx, pre)

	for i := range result {
		for j := range result[i].Webshell {
			ws := result[i].Webshell[j]
			// 容器中可能没有 passwd 和 group 文件，且这里也不要求一定有值，所以没有判错
			uid, _ := scannerUtils.FileUID(ws.Filename)
			uname := uidMap[uid].Username
			gid, _ := scannerUtils.FileUID(ws.Filename)
			gname := gidMap[gid].Name
			ws.Mod = fmt.Sprintf("%s %s %s", ws.Mod, uname, gname)
			result[i].Webshell[j] = ws
		}
	}

	return result
}
