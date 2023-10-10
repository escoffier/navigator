package aviraengin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/avira"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
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
	Status   string // 执行的状态：
}

func (vi *AviraClient) LogStr() string {
	str := fmt.Sprintf("ClientNO=%d Status=%s SavClient=%s", vi.ClientNO, vi.Status, vi.Client.ServerAddr)
	return str
}

type AviraSrv struct {
	MalwareEnginName string
	ClientChan       chan *avira.SavClient
	Client           *avira.SavClient // 应该起多个 client
	ClientPoll       []*AviraClient
	WorkingVersion   imagesecModel.DBVersionInfo
	LastVersion      imagesecModel.DBVersionInfo
	LastDBPathInfo   imagesecModel.DBPathInfo
	WorkDBPathInfo   imagesecModel.DBPathInfo
	AviraServer      *avira.SavServer
	TaskWG           sync.WaitGroup // 任务执行情况
	ClientWG         sync.Locker
	ClientPollCnt    int
	ServerAddr       string
	ScanTimeout      int64
	Log              *scannerUtils.LogEvent
}

func NewSavServer() (*AviraSrv, error) {
	singleAviraSrv.WG.Lock()
	defer singleAviraSrv.WG.Unlock()

	if singleAviraSrv.AviraSrv != nil {
		return singleAviraSrv.AviraSrv, nil
	}

	srv := &AviraSrv{
		ServerAddr:       fmt.Sprintf("tcp:127.0.0.1:%d", avira.DefaultSavApiListenAddr),
		MalwareEnginName: consts.AviraName,
		ClientChan:       make(chan *avira.SavClient),
		WorkingVersion:   imagesecModel.DBVersionInfo{},
		LastVersion:      imagesecModel.DBVersionInfo{},
		LastDBPathInfo:   types.GetAviraDBPathInfo(),
		WorkDBPathInfo:   types.GetAviraDBPathInfo(),
		TaskWG:           sync.WaitGroup{},
		ClientWG:         &sync.Mutex{},
		ScanTimeout:      5 * 60, // 单个文件扫描的超时时间2分种
		ClientPollCnt:    20,     // FIXME 后期应该做成可配置的
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("AviraSrv"),
			scannerUtils.WithModule(consts.ModelImageScan),
		),
	}
	srv.ClientPoll = make([]*AviraClient, 0)

	if err := srv.generateVersionFromWorkPath(); err != nil {
		return nil, err
	}
	// 后期功能
	// srv.WorkingVersion = srv.getVersionFromFile(context.Background(), srv.WorkDBPathInfo.WorkVersionFilename)

	if err := os.MkdirAll(srv.WorkDBPathInfo.UpdatePath, os.ModePerm); err != nil {
		return nil, err
	}

	srv.AviraServer = NewSavEngin()

	if err := srv.CreateClientPoll(context.Background()); err != nil {
		return nil, err
	}

	singleAviraSrv.AviraSrv = srv

	return singleAviraSrv.AviraSrv, nil
}

func NewAviraUpdateSrv() *AviraSrv {
	srv := &AviraSrv{
		MalwareEnginName: consts.AviraName,
		WorkDBPathInfo:   types.GetAviraDBPathInfo(),
	}

	srv.WorkingVersion = srv.getVersionFromFile(context.Background(), srv.WorkDBPathInfo.WorkVersionFilename)

	return srv
}

// 会持续检测进程是否存活
func NewSavEngin() *avira.SavServer {
	savServer := avira.NewSavServer(avira.WithListenPort(avira.DefaultSavApiListenAddr))
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
	return savServer
}

func (s *AviraSrv) CreateClientPoll(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	cnt := 0
	for i := 0; i < s.ClientPollCnt; i++ {
		for {
			<-ticker.C
			client, err := avira.NewSavClient(s.ServerAddr)
			if err != nil {
				cnt++
				if cnt > s.ClientPollCnt*5 {
					s.Log.Info().Msg("AviraSrv not CreateClientPoll")
					return fmt.Errorf("can not create aviara client")
				}
				continue
			}
			cl := &AviraClient{
				ClientNO: i,
				Client:   client,
				Status:   AviraClientUnUsing,
			}
			s.ClientPoll = append(s.ClientPoll, cl)
			break
		}
	}
	s.Log.Info().Int("pollCnt", len(s.ClientPoll)).Msg("AviraSrv CreateClientPoll")
	return nil
}

func (s *AviraSrv) GenEnginChan(ctx context.Context) {
	s.getEnginBackground(ctx)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("panic recover GenEnginChan")
			}
		}()

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			// FIXME 小红伞请求过多的会拒绝连接，所以要做控制 限制并发
			<-ticker.C
			// 下期功能
			if lastPath, err := s.getLastUpdatePath(ctx); err == nil {
				verPath := path.Join(s.LastDBPathInfo.UpdatePath, lastPath, s.MalwareEnginName, consts.VersionStr)
				s.LastVersion = s.getVersionFromFile(ctx, verPath)
				s.LastDBPathInfo.UpdateZipFilename = path.Join(s.LastDBPathInfo.UpdatePath, fmt.Sprintf("%s.zip", lastPath))
				s.LastDBPathInfo.UpdateUnZipPath = path.Join(s.LastDBPathInfo.UpdatePath, lastPath)
			}

			if !s.needUpdate(ctx) {
				s.Log.Debug().Interface("LastDBPathInfo",
					s.LastDBPathInfo).Msg("AviraSrv GenEnginChan do not need update db")

				if s.Client == nil {
					s.Log.Debug().Msg("AviraSrv GenEnginChan client is nil")
					client, err := avira.NewSavClient(s.ServerAddr)
					if err != nil {
						ticker.Reset(10 * time.Second)
						s.Log.Err(err).Msg("AviraSrv NewSavClient")
						<-ticker.C
						continue
					}
					ticker.Reset(time.Second)
					s.Client = client
				}

				s.Log.Info().Msg("AviraSrv GenEnginChan send client")
				s.ClientChan <- s.Client
				continue
			}

			s.Log.Debug().Interface("LastDBPathInfo", s.LastDBPathInfo).Msg("AviraSrv GenEnginChan need update db")

			s.TaskWG.Wait() // 等待任务执行完成

			if err := s.AviraServer.KillServer(); err != nil {
				s.Log.Err(err).Msg("AviraSrv GenEnginChan Close AviraServer")
				<-ticker.C
				continue
			}

			s.Log.Debug().Msg("AviraSrv GenEnginChan killed server")

			// copy all db files
			osCMD := exec.Command("cp", "-rf", s.getUpdateClamavPath(ctx), s.WorkDBPathInfo.WorkPath)
			s.Log.Info().Strs("cmd", osCMD.Args).Msg("GenEnginChan copy db file")

			if err := osCMD.Run(); err != nil {
				s.Log.Err(err).Strs("cmd", osCMD.Args).Msg("GenEnginChan copy db file")
				<-ticker.C
				continue
			}

			// restart server
			s.AviraServer = NewSavEngin()
			s.Client = nil

			s.Log.Debug().Interface("LastVersion", s.LastVersion).Msg("GenEnginChan restart server")

			s.WorkingVersion = s.LastVersion

			// 删除临时文件
			_ = os.RemoveAll(s.LastDBPathInfo.UpdateUnZipPath)
			// 向子集群及和节点全部发送完之后才能删除
			// _ = os.RemoveAll(s.LastDBPathInfo.UpdateZipFilename)
			s.Log.Debug().Interface("LastDBPathInfo", s.LastDBPathInfo).Msg("GenEnginChan")
		}
	}()
}

func (s *AviraSrv) needUpdate(_ context.Context) bool {
	if s.LastVersion.Version == "" || s.LastDBPathInfo.UpdateUnZipPath == "" {
		return false
	}

	if (s.WorkingVersion.Version != "" && s.LastVersion.Version == "") ||
		s.WorkingVersion.Version == s.LastVersion.Version && s.WorkingVersion.Hash == s.LastVersion.Hash {
		return false
	}
	if s.WorkingVersion.Version > s.LastVersion.Version {
		return false
	}

	return true
}

// 会卡死，一定要设置超时
func (s *AviraSrv) ScanFile(_ context.Context, engin *avira.SavClient, filename string) ([]avira.Malware, error) {

	s.TaskWG.Add(1)
	defer s.TaskWG.Done()

	malware, err := engin.ScanFile(filename)
	if err != nil {
		s.Log.Err(err).Str("filename", filename).
			Str("MalwareEnginName", s.MalwareEnginName).Msg("AviraSrv ScanFile")
		return nil, err
	}

	return malware, nil
}

type AviraScanRes struct {
	data []avira.Malware
	err  error
}

func (s *AviraSrv) Task(ctx context.Context, cli *avira.SavClient, filename string) chan AviraScanRes {
	out := make(chan AviraScanRes)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("module", "imagescan").Str("Stack", string(debug.Stack())).Msg("AviraSrv panic")
			}
		}()

		data, err := s.ScanFile(ctx, cli, filename)
		res := AviraScanRes{
			data: data,
			err:  err,
		}
		out <- res

		s.Log.Debug().Str("filename", filename).
			Str("MalwareEnginName", s.MalwareEnginName).Msg("AviraSrv scan end")
	}()
	return out
}

// 病毒扫描可能卡死
func (s *AviraSrv) DoScanFile(ctx context.Context, client *avira.SavClient, filename string) ([]avira.Malware, error) {
	ctxT, can := context.WithTimeout(ctx, time.Second*time.Duration(s.ScanTimeout))
	defer can()

	for {
		select {
		case <-ctxT.Done():
			s.Log.Info().Str("filename", filename).Msg("AviraSrv time out")
			return []avira.Malware{}, fmt.Errorf("scan %s timeout", filename)
		case res := <-s.Task(ctxT, client, filename):
			return res.data, res.err
		}
	}
}

// 获取引擎
func (s *AviraSrv) GetClient(ctx context.Context) (*AviraClient, error) {
	start := time.Now().Unix()
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	for {
		s.ClientWG.Lock()
		for i := range s.ClientPoll {
			eng := s.ClientPoll[i]
			if eng.Status == AviraClientUnUsing {
				s.ClientPoll[i].Status = AviraClientUsing
				eng.Status = AviraClientUsing
				s.ClientWG.Unlock()
				s.Log.Info().Str("engin", eng.LogStr()).Msg("AviraSrv GetClient")
				return eng, nil
			}
		}
		s.ClientWG.Unlock()
		s.Log.Info().Msg("AviraSrv not get client and wait next")

		if time.Now().Unix()-start > s.ScanTimeout*int64(s.ClientPollCnt) {
			err := fmt.Errorf("get avira client engin timeout")
			s.Log.Err(err).Msg("AviraSrv get client timeout")
			return nil, err
		}
		<-ticker.C
	}
}

const (
	AviraClientUsing    = "using"    // 使用中
	AviraClientUnUsing  = "notUse"   // 未使用但是正常的
	AviraClientAbnormal = "abnormal" // 如果执行超时，就认为是异常，就应该用 poll 中删除 (先不实现)
)

// 归还引擎
func (s *AviraSrv) BackClient(ctx context.Context, eng *AviraClient) {
	if eng == nil {
		return
	}
	s.Log.Debug().Str("engin", eng.LogStr()).Msg("AviraSrv BackClient start")
	s.ClientWG.Lock()
	defer s.ClientWG.Unlock()
	for i := range s.ClientPoll {
		en := s.ClientPoll[i]
		if en.ClientNO == eng.ClientNO {
			s.ClientPoll[i].Status = AviraClientUnUsing
			en.Status = AviraClientUnUsing
		}
	}
	s.Log.Info().Str("engin", eng.LogStr()).Msg("AviraSrv BackClient end")
}

// 当用户在界面上更新病毒库后，只有当获取扫描 engin 时才会去加载新的病毒库，如果一直没有扫描任务则一直不会加载病毒库
func (s *AviraSrv) getEnginBackground(_ context.Context) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("panic recover GenEnginChan")
			}
		}()

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			<-s.ClientChan
		}
	}()
}

func (s *AviraSrv) getVersionFromFile(ctx context.Context, filename string) imagesecModel.DBVersionInfo {
	if !util.FileExists(s.WorkDBPathInfo.WorkVersionFilename) {
		return imagesecModel.DBVersionInfo{}
	}

	fileContent, err := os.ReadFile(filename)
	if err != nil {
		s.Log.Err(err).Str("filename", filename).Msg("getVersionFromFile")
		return imagesecModel.DBVersionInfo{}
	}
	t := AviraVersion{}
	if err := json.Unmarshal(fileContent, &t); err != nil {
		s.Log.Err(err).Str("filename", filename).Msg("getVersionFromFile")
		return imagesecModel.DBVersionInfo{}
	}
	vv := imagesecModel.DBVersionInfo{
		DBType:   consts.AviraName,
		Version:  t.AviraVersion.Version,
		UpdateAt: t.UpdateTime,
		Comment:  t.AviraVersion.Comment,
		Hash:     t.AviraVersion.Hash,
	}
	return vv
}

func (s *AviraSrv) UpdateDB(ctx context.Context, param imagesecModel.UpdateDbParam) (*imagesecModel.ScanDbMeta, error) {

	pa := types.GetAviraDBPathInfo()
	pa = pa.DeepCopy()

	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())

	pa.UpdateZipFilename = path.Join(pa.UpdatePath, timestamp+".zip")
	pa.UpdateUnZipPath = path.Join(pa.UpdatePath, timestamp)

	if err := os.WriteFile(pa.UpdateZipFilename, param.Data, os.ModePerm); err != nil {
		s.Log.Err(err).Msg("UpdateDB")
		return nil, err
	}

	if err := util.Unzip(pa.UpdateZipFilename, pa.UpdateUnZipPath, consts.DBPassword); err != nil {
		s.Log.Err(err).Msg("ClamavSrv not zip file")
		return nil, err
	}

	pa.UpdateVersionFilename = path.Join(pa.UpdateUnZipPath, s.MalwareEnginName, consts.VersionStr)

	version := s.getVersionFromFile(ctx, pa.UpdateVersionFilename)

	s.Log.Info().Str("dbType", param.DbType).Str("dbVersion", version.Version).
		Str("zipFile", pa.UpdateZipFilename).Str("zipPath", pa.UpdateUnZipPath).Msg("UpdateDB ok")

	// s.LastDBPathInfo = pa
	// s.LastVersion = version

	dbMeta := &imagesecModel.ScanDbMeta{
		DBType:    consts.AviraName,
		DBVersion: version.Version,
		Enable:    true,
		DBMeta: imagesecModel.DBMeta{
			DBVersion:     version.Version,
			DBComment:     "",
			DBHash:        version.Hash,
			EngineHash:    "",
			EngineVersion: "",
			EngineComment: "",
			Enable:        true,
			Updater:       param.Updater,
		},
	}

	return dbMeta, nil
}

func (s *AviraSrv) getUpdateVersionFilename(_ context.Context, pa imagesecModel.DBPathInfo) string {
	if pa.UpdateUnZipPath == "" {
		return ""
	}
	return pa.UpdateUnZipPath + "/" + s.MalwareEnginName + "/" + consts.VersionStr
}

// 默认获取version成功即二进制和病毒库可用
func (s *AviraSrv) getVersionFromBinFile() (string, error) {
	cmd := exec.Command("chmod", "+x", s.WorkDBPathInfo.BinFilename)
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	cmd = exec.Command(s.WorkDBPathInfo.BinFilename, "--version")
	out, err := cmd.CombinedOutput()
	version := ""
	if err != nil && !strings.Contains(err.Error(), "exit status 101") {
		s.Log.Err(err).Msg("get avira version")
		return version, err
	}
	strOut := string(out)
	/*
			output
			Product build:            Linux (x86_64, glibc 2.12)
			SAVAPI service version:   4.15.8.43

			Component versions:
		    SAVAPI library version:  4.15.8.43
		    Engine version:          8.3.64.140
		    Packlib version:         8.5.2.48
		    VDF version:             8.19.15.20
		    APC library version:     2.11.1.3
	*/
	str := strings.Split(strOut, "\n")
	for k := range str {
		if !strings.Contains(str[k], "Packlib") {
			continue
		}
		versionLine := strings.Split(str[k], ":")
		if len(versionLine) < 2 {
			return version, fmt.Errorf("not get savapi version")
		}
		version = strings.TrimSpace(versionLine[1])
	}
	if version == "" {
		return version, fmt.Errorf("can't get version may be fault db")
	}
	return version, nil
}

// 默认获取version成功即二进制和病毒库可用
func (s *AviraSrv) getVersionLastVersion(ctx context.Context) (imagesecModel.DBVersionInfo, error) {
	dir, err := os.ReadDir(s.LastDBPathInfo.UpdatePath)
	if err != nil {
		s.Log.Err(err).Str("path", s.LastDBPathInfo.UpdatePath).Msg("getVersionLastVersion")
		return imagesecModel.DBVersionInfo{}, err
	}
	dirs := make([]int, 0)

	for _, fi := range dir {
		if !fi.IsDir() {
			if tm, err := strconv.Atoi(fi.Name()); err == nil {
				dirs = append(dirs, tm)
			}
		}
	}
	sort.Ints(dirs)
	if len(dirs) == 0 {
		return imagesecModel.DBVersionInfo{}, fmt.Errorf("not find last db")
	}
	first := dirs[0]

	filePath := path.Join(s.LastDBPathInfo.UpdatePath, fmt.Sprintf("%d", first), s.MalwareEnginName)
	version := s.getVersionFromFile(ctx, fmt.Sprintf("%s/%s", filePath, consts.VersionStr))
	return version, nil
}

// 获取当前执行的版本号
func (s *AviraSrv) generateVersionFromWorkPath() error {
	if util.FileExists(s.WorkDBPathInfo.WorkVersionFilename) {
		return nil
	}
	ver, err := s.getVersionFromBinFile()
	if err != nil {
		s.Log.Err(err).Msg("generateVersionFromWorkPath")
		return err
	}
	md5Str, err := util.Md5FromFile(s.WorkDBPathInfo.BinFilename)

	if err != nil {
		s.Log.Err(err).Msg("generateVersionFromWorkPath Md5FromFile")
		return err
	}
	version := AviraVersion{
		CompressDBVersion: "auto generate",
		AviraVersion: struct {
			Version string `json:"version"`
			Comment string `json:"comment"`
			Hash    string `json:"hash"`
		}{
			Version: ver,
			Comment: "default",
			Hash:    md5Str,
		},
		UpdateTime: time.Now().UnixMilli(),
	}

	verByte, err := json.Marshal(version)
	if err != nil {
		s.Log.Err(err).Msg("generateVersionFromWorkPath Marshal")
		return err
	}
	err = os.WriteFile(s.WorkDBPathInfo.WorkVersionFilename, verByte, 0600)
	if err != nil {
		s.Log.Err(err).Msg("generateVersionFromWorkPath do not write version file")
		return err
	}
	return nil
}

func (s *AviraSrv) getLastUpdatePath(_ context.Context) (string, error) {
	dir, err := os.ReadDir(s.LastDBPathInfo.UpdatePath)
	if err != nil {
		s.Log.Err(err).Str("path", s.LastDBPathInfo.UpdatePath).Msg("getVersionLastVersion")
		return "", err
	}
	dirs := make([]int, 0)

	for _, fi := range dir {
		if fi.IsDir() {
			if tm, err := strconv.Atoi(fi.Name()); err == nil {
				dirs = append(dirs, tm)
			}
		}
	}
	sort.Ints(dirs)
	if len(dirs) == 0 {
		// 如果没有升级过就不会有这个目录，所以这里最好 debug 日志
		s.Log.Debug().Msg("not find last db path")
		return "", fmt.Errorf("not find last db path")
	}
	return fmt.Sprintf("%d", dirs[0]), nil
}

type AviraVersion struct {
	CompressDBVersion string `json:"compressDBVersion"`
	AviraVersion      struct {
		Version string `json:"version"`
		Comment string `json:"comment"`
		Hash    string `json:"hash"`
	} `json:"AviraVersion"`
	UpdateTime int64 `json:"updateTime"`
}

func (s *AviraSrv) getUpdateClamavPath(_ context.Context) string {
	if s.LastDBPathInfo.UpdateUnZipPath == "" {
		return ""
	}
	return path.Join(s.LastDBPathInfo.UpdateUnZipPath, s.MalwareEnginName)
}
