package aviraengin

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"go.uber.org/atomic"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/avira"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var singleAviraSrv *SingleAviraSrv

type SingleAviraSrv struct {
	AviraSrv *AviraSrv
	WG       sync.Locker
}

// 这样才保险
func init() {
	singleAviraSrv = &SingleAviraSrv{
		AviraSrv: nil,
		WG:       &sync.Mutex{},
	}
}

type AviraClient struct {
	ClientNO int
	Client   *avira.SavClient
	Status   string // 执行的状态
}

type AviraSrv struct {
	EnginName        string
	ClientPoll       []*AviraClient
	WorkingVersion   imagesecModel.DBVersionInfo
	LastVersion      imagesecModel.DBVersionInfo
	LastDBPathInfo   imagesecModel.DBPathInfo
	WorkDBPathInfo   imagesecModel.DBPathInfo
	AviraServer      *avira.SavServer
	TaskWG           *sync.WaitGroup // 任务执行情况
	ClientWG         sync.Locker     // 保证只会有一个线程更新ClientPoll
	ClientPollCnt    int
	ServerAddr       string
	ScanTimeout      int64
	Log              *scannerUtils.LogEvent
	MaxSingeFileSize int64         // 过于大的文件不再扫描
	HeatBeat         *atomic.Int64 // 心跳时间，如果长时间没有扫描任务，最好停止小红伞服务
}

func NewSavServer(opts ...Option) (*AviraSrv, error) {
	singleAviraSrv.WG.Lock()
	defer singleAviraSrv.WG.Unlock()

	if singleAviraSrv.AviraSrv != nil {
		return singleAviraSrv.AviraSrv, nil
	}

	srv := &AviraSrv{
		ServerAddr:       fmt.Sprintf("tcp:127.0.0.1:%d", consts.DefaultAviraSavServerListenPort),
		EnginName:        consts.AviraName,
		WorkingVersion:   imagesecModel.DBVersionInfo{},
		LastVersion:      imagesecModel.DBVersionInfo{},
		LastDBPathInfo:   types.GetAviraDBPathInfo(),
		WorkDBPathInfo:   types.GetAviraDBPathInfo(),
		TaskWG:           &sync.WaitGroup{},
		ClientWG:         &sync.Mutex{},
		ScanTimeout:      5 * 60, // 单个文件扫描的超时时间2分种
		ClientPollCnt:    20,     // 应该做成可配置的,测试超过24个时就会卡死，不会直接报错，会直接卡死
		MaxSingeFileSize: (1 << 20) * 10,
		HeatBeat:         atomic.NewInt64(0),
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("AviraSrv"),
			scannerUtils.WithModule(consts.ModuleImageScan),
		),
	}

	for i := range opts {
		opts[i](srv)
	}

	srv.ClientPoll = make([]*AviraClient, 0)

	// 后期功能
	// if err := srv.generateVersionFromWorkPath(); err != nil {
	// 	return nil, err
	// }
	// srv.WorkingVersion = srv.getVersionFromFile(context.Background(), srv.WorkDBPathInfo.WorkVersionFilename)
	//
	// if err := os.MkdirAll(srv.WorkDBPathInfo.UpdatePath, os.ModePerm); err != nil {
	// 	return nil, err
	// }

	srv.AviraServer = NewSavEngin(avira.WithListenPort(consts.DefaultAviraSavServerListenPort))

	if err := srv.CreateClientPoll(context.Background()); err != nil {
		return nil, err
	}

	// 监控client
	_ = srv.monitorClient(context.Background())
	// 监控服务
	// _ = srv.monitorService(context.Background())

	srv.HeatBeat = atomic.NewInt64(time.Now().Unix())

	singleAviraSrv.AviraSrv = srv

	return singleAviraSrv.AviraSrv, nil
}

// 会持续检测进程是否存活
func NewSavEngin(opts ...avira.Option) *avira.SavServer {

	savServer := avira.NewSavServer()
	for i := range opts {
		opts[i](savServer)
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		savServer.StartServer()
	}()
	// 一定要做这一步，不然就会出错，具体原因不明白
	time.Sleep(time.Minute) // 等实例化好

	logging.Get().Info().Msg("AviraSrv NewSavEngin")
	return savServer
}

func (s *AviraSrv) ImageScan(ctx context.Context, pre *imagesecTypes.PrepareScan) []imagesecTypes.ScanJobResult {
	s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).Str(consts.ScanJobLogName, "AviraSrv").Msg("scan job start")
	defer s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).Str(consts.ScanJobLogName, "AviraSrv").Msg("scan job end")

	result := make([]imagesecTypes.ScanJobResult, 0)
	out := make(chan imagesecTypes.ScanJobResult)
	defer close(out)
	for i := range pre.Layers {
		ly := pre.Layers[i]
		go func(ctx context.Context, ly *imagesecTypes.ImageLayer, pre *imagesecTypes.PrepareScan, out chan imagesecTypes.ScanJobResult) {
			s.scanJob(ctx, ly, pre, out)
		}(ctx, ly, pre, out)
	}
	for i := 0; i < len(pre.Layers); i++ {
		res := <-out
		result = append(result, res)
	}

	return result
}

func (s *AviraSrv) scanJob(ctx context.Context, ly *imagesecTypes.ImageLayer, pre *imagesecTypes.PrepareScan, out chan imagesecTypes.ScanJobResult) {

	res := imagesecTypes.ScanJobResult{
		Layer: ly.Digest,
		Issue: imagesecModel.MalwareCacheData,
	}

	if pre.Subtask.MalwareCache.In(ly.Digest) {
		res.InCache = true
		s.Log.Debug().Str("subtask", pre.Subtask.LogStr()).Str("layer", ly.Digest).
			Str("Issue", imagesecModel.MalwareCacheData).Msg("scan layer data in cache")
		out <- res
		return
	}

	fis := make([]string, 0)

	err := filepath.Walk(ly.LayerFilePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !FilterMalware(ly, path, info) {
			return nil
		}
		fis = append(fis, path)
		return nil
	})

	if err != nil {
		s.Log.Err(err).Interface("layer", ly).Msg("AviraSrv Scan")
		res.Errors = append(res.Errors, err)
		out <- res
		return
	}
	if len(fis) == 0 {
		out <- res
		return
	}

	mal, err := s.ScanFile(ctx, fis)
	if err != nil {
		s.Log.Err(err).Int("fileCnt", len(fis)).Msg("AviraSrv Scan")
		res.Errors = append(res.Errors, err)
		out <- res
		return
	}

	for j := range mal {
		ma := imagesecTypes.AviraScanResult2{
			Filename:    mal[j].Filename,
			MD5:         scannerUtils.GetFileMd5(mal[j].Filename),
			Type:        mal[j].Type,
			Name:        mal[j].Name,
			Description: mal[j].Description,
			Layer:       ly.Digest,
		}
		res.AviraScan = append(res.AviraScan, ma)
	}

	res.Scanned = true
	out <- res
}

func (s *AviraSrv) UpdateDB(ctx context.Context, param imagesecModel.UpdateDbParam) error {

	pa := types.GetAviraDBPathInfo()
	pa = pa.DeepCopy()

	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())

	pa.UpdateZipFilename = path.Join(pa.UpdatePath, timestamp+".zip")
	pa.UpdateUnZipPath = path.Join(pa.UpdatePath, timestamp)

	if err := os.WriteFile(pa.UpdateZipFilename, param.Data, os.ModePerm); err != nil {
		s.Log.Err(err).Msg("UpdateDB")
		return err
	}

	if err := util.Unzip(pa.UpdateZipFilename, pa.UpdateUnZipPath, consts.DBPassword); err != nil {
		s.Log.Err(err).Msg("ClamavSrv not zip file")
		return err
	}

	pa.UpdateVersionFilename = path.Join(pa.UpdateUnZipPath, s.EnginName, consts.VersionStr)

	version := s.getVersionFromFile(ctx, pa.UpdateVersionFilename)

	s.Log.Info().Str("dbType", param.DbType).Str("dbVersion", version.Version).
		Str("zipFile", pa.UpdateZipFilename).Str("zipPath", pa.UpdateUnZipPath).Msg("UpdateDB ok")

	return nil
}

func (s *AviraSrv) Collect(ctx context.Context, rootDir string, filter scannerUtils.FileFilter) ([]string, error) {
	res := make([]string, 0)
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if filter(info) {
			res = append(res, path)
		}
		return nil
	})
	return res, err
}

func FilterMalware(ly *imagesecTypes.ImageLayer, filename string, fi os.FileInfo) bool {

	/*
		这几个目录加白
		/proc: 包含系统进程信息。
		/sys: 包含与内核和硬件相关的信息。
		/dev: 包含设备文件。
		/run: 包含运行时信息。
		/var/log: 包含系统和应用程序日志
	*/

	dn := ly.ContainerFilename(filename)

	if !strings.HasPrefix(dn, "/") {
		dn = "/" + dn
	}

	if strings.HasPrefix(dn, "/proc") || strings.HasPrefix(dn, "/sys") ||
		strings.HasPrefix(dn, "/dev") || strings.HasPrefix(dn, "/var/log") {
		return false
	}

	return fi.Mode().IsRegular()
}
