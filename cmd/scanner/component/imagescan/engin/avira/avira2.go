package aviraengin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/rand"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/avira"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (vi *AviraClient) LogStr() string {
	str := fmt.Sprintf("ClientNO=%d Status=%s SavClient=%s", vi.ClientNO, vi.Status, vi.Client.ServerAddr)
	return str
}

func (s *AviraSrv) CreateClientPoll(ctx context.Context) error {
	/*
		PoolScanners 24
		#
		# Specifies the SAVAPI workers number. SAVAPI will start with the specified
		# number of workers. SAVAPI will not accept an infinite number of scanners.
		# The maximum accepted number is 300.
		#
		# Available values: 1 - 300
		#
		# Default value: 24

		PoolConnections 48
		#
		# Specifies the pending connections queue length. SAVAPI will not accept an
		# infinite number of pending connections. The maximum accepted number is 900.
		#
		# Available values: 1 - 900
		#
		# Default value: 48

	*/

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
			s.Log.Info().Int("clintCnt", i).Msg("NewSavClient create a client")
			s.ClientPoll = append(s.ClientPoll, cl)
			break
		}
	}
	s.Log.Info().Int("pollCnt", len(s.ClientPoll)).Msg("AviraSrv CreateClientPoll")
	return nil
}

func (s *AviraSrv) GenEnginChan(ctx context.Context) {

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("panic recover GenEnginChan")
			}
		}()

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			<-ticker.C
			// 下期功能
			if lastPath, err := s.getLastUpdatePath(ctx); err == nil {
				verPath := path.Join(s.LastDBPathInfo.UpdatePath, lastPath, s.EnginName, consts.VersionStr)
				s.LastVersion = s.getVersionFromFile(ctx, verPath)
				s.LastDBPathInfo.UpdateZipFilename = path.Join(s.LastDBPathInfo.UpdatePath, fmt.Sprintf("%s.zip", lastPath))
				s.LastDBPathInfo.UpdateUnZipPath = path.Join(s.LastDBPathInfo.UpdatePath, lastPath)
			}

			if !s.needUpdate(ctx) {
				s.Log.Debug().Interface("LastDBPathInfo",
					s.LastDBPathInfo).Msg("AviraSrv GenEnginChan do not need update db")

				// if s.Client == nil {
				// 	s.Log.Debug().Msg("AviraSrv GenEnginChan client is nil")
				// 	client, err := avira.NewSavClient(s.ServerAddr)
				// 	if err != nil {
				// 		ticker.Reset(10 * time.Second)
				// 		s.Log.Err(err).Msg("AviraSrv NewSavClient")
				// 		<-ticker.C
				// 		continue
				// 	}
				// 	ticker.Reset(time.Second)
				// }
				//
				// s.Log.Info().Msg("AviraSrv GenEnginChan send client")
				// continue
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

// 可能会卡死，一定要设置超时
func (s *AviraSrv) ScanFile(ctx context.Context, filenames []string) ([]imagesecTypes.AviraScanResult2, error) {
	res := make([]imagesecTypes.AviraScanResult2, 0)
	if len(filenames) == 0 {
		return res, nil
	}

	s.TaskWG.Add(1)
	defer s.TaskWG.Done()

	cli, err := s.GetClient(ctx)
	if err != nil {
		return nil, err
	}
	defer s.BackClient(ctx, cli)

	engin := cli.Client

	s.Log.Info().Int("fileCnt", len(filenames)).Str("EnginName", s.EnginName).Msg("AviraSrv ScanFile")
	for j := range filenames {
		fi := filenames[j]
		// engin.ScanFile 会卡死
		malware, err := s.DoTask(ctx, engin, fi)
		if err != nil {
			s.Log.Err(err).Str("filenames", fi).
				Str("EnginName", s.EnginName).Msg("AviraSrv ScanFile")
			/*
				1,write tcp 127.0.0.1:56610->127.0.0.1:9200: write: broken pipe
				2，扫描超时
				3,read tcp 127.0.0.1:54936->127.0.0.1:9200:use of closed network connection
				这种情况下就要重新生成 client 了
			*/
			if strings.Contains(err.Error(), "write: broken pipe") || errors.Is(err, ErrScanTimeout) ||
				strings.Contains(err.Error(), "closed network connection") {
				s.Log.Error().Int("clientNo", cli.ClientNO).Msg("AviraSrv client is abnormal need create new client")
				cli.Status = AviraClientAbnormal
				return nil, err
			}
			// just log
			continue
		}
		for i := range malware {
			res = append(res, imagesecTypes.AviraScanResult2{
				Filename:    fi,
				MD5:         scannerUtils.GetFileMd5(fi),
				Type:        malware[i].Type,
				Name:        malware[i].Name,
				Description: malware[i].Desc,
			})
		}
	}

	return res, nil
}

type AviraScanRes struct {
	data []avira.Malware
	err  error
}

func (s *AviraSrv) scanWithTimeout(ctx context.Context, eng *avira.SavClient, filename string) chan AviraScanRes {
	out := make(chan AviraScanRes)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("AviraSrv panic")
			}
		}()

		data, err := eng.ScanFile(filename)
		res := AviraScanRes{
			data: data,
			err:  err,
		}
		out <- res

		s.Log.Debug().Str("filename", filename).Str("EnginName", s.EnginName).Msg("AviraSrv scan end")
	}()
	return out
}

// 获取引擎
func (s *AviraSrv) GetClient(ctx context.Context) (*AviraClient, error) {
	start := time.Now().Unix()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		running, err := s.AviraServer.IsServerRunning()
		if s.HeatBeat.Load() == 0 || err != nil || !running {
			// 重新启动
			s.AviraServer = NewSavEngin(avira.WithListenPort(consts.DefaultAviraSavServerListenPort))
			if err := s.CreateClientPoll(ctx); err != nil {
				s.Log.Err(err).Msg("can not CreateClientPoll AviraServer")
				continue
			}
			s.Log.Info().Msg("rerun AviraSrv success")
		}

		s.ClientWG.Lock()
		for i := range s.ClientPoll {
			eng := s.ClientPoll[i]
			if eng.Status == AviraClientUnUsing {
				s.ClientPoll[i].Status = AviraClientUsing
				eng.Status = AviraClientUsing
				s.ClientWG.Unlock()
				s.Log.Debug().Str("engin", eng.LogStr()).Msg("AviraSrv GetClient")
				s.HeatBeat.Store(time.Now().Unix())
				return eng, nil
			}
		}
		s.ClientWG.Unlock()
		s.Log.Debug().Msg("AviraSrv not get client and wait next")

		if time.Now().Unix()-start > s.ScanTimeout*int64(s.ClientPollCnt) {
			err := fmt.Errorf("get avira client engin timeout")
			s.Log.Err(err).Msg("AviraSrv get client timeout")
			return nil, err
		}

		ticker.Reset(time.Duration(rand.Int63nRange(1000, 3000)) * time.Millisecond)
		<-ticker.C
	}
}

func (s *AviraSrv) monitorClient(ctx context.Context) error {
	go func() {
		if r := recover(); r != nil {
			s.Log.Error().Str("stack", string(debug.Stack())).Msg("AviraSrv monitorClient")
		}
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			s.ClientWG.Lock()

			for i := range s.ClientPoll {
				ci := s.ClientPoll[i]
				if ci.Status != AviraClientAbnormal {
					continue
				}
				_ = ci.Client.Close()

				s.Log.Info().Int("clintCnt", i).Msg("AviraSrv client is abnormal need recreate a new client")
				// 新建一个
				cli, err := avira.NewSavClient(s.ServerAddr)
				if err != nil {
					s.Log.Info().Msg("AviraSrv can not create a new client")
					continue
				}
				cl := &AviraClient{
					ClientNO: ci.ClientNO,
					Client:   cli,
					Status:   AviraClientUnUsing,
				}
				s.ClientPoll[i] = cl
				s.Log.Info().Int("clintCnt", i).Msg("AviraSrv create a new client")
			}
			s.ClientWG.Unlock()
		}
	}()

	return nil
}

const (
	AviraClientUsing    = "using"    // 使用中
	AviraClientUnUsing  = "notUse"   // 未使用但是正常的
	AviraClientAbnormal = "abnormal" // 如果执行超时，就认为是异常，就应该在连接池中删除 (先不实现)
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
			if eng.Status == AviraClientUsing {
				s.ClientPoll[i].Status = AviraClientUnUsing
				en.Status = AviraClientUnUsing
			}
			if eng.Status == AviraClientAbnormal {
				s.ClientPoll[i].Status = AviraClientAbnormal
			}
		}
	}
	s.Log.Debug().Str("engin", eng.LogStr()).Msg("AviraSrv BackClient end")
}

// 病毒扫描可能卡死
func (s *AviraSrv) DoTask(ctx context.Context, eng *avira.SavClient, filename string) ([]avira.Malware, error) {
	ctxT, can := context.WithTimeout(ctx, time.Minute*2)
	defer can()

	for {
		select {
		case <-ctxT.Done():
			s.Log.Error().Str("filename", filename).Msg("AviraSrv time out")
			return []avira.Malware{}, ErrScanTimeout
		case res := <-s.scanWithTimeout(ctxT, eng, filename):
			return res.data, res.err
		}
	}
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

func (s *AviraSrv) getUpdateVersionFilename(_ context.Context, pa imagesecModel.DBPathInfo) string {
	if pa.UpdateUnZipPath == "" {
		return ""
	}
	return pa.UpdateUnZipPath + "/" + s.EnginName + "/" + consts.VersionStr
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

	filePath := path.Join(s.LastDBPathInfo.UpdatePath, fmt.Sprintf("%d", first), s.EnginName)
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
	return path.Join(s.LastDBPathInfo.UpdateUnZipPath, s.EnginName)
}

// 对部分文件不进行病毒扫描
// 后续可能增加逻辑
func (s *AviraSrv) filterAviraScan(ctx context.Context, fn string) bool {
	fi, err := os.Stat(fn)
	if err != nil {
		return false
	}
	if fi.Size() == 0 {
		return false
	}
	if fi.Size() > s.MaxSingeFileSize {
		return false
	}
	if fi.IsDir() {
		return false
	}
	if !fi.Mode().IsRegular() {
		return false
	}
	return true
}

func (s *AviraSrv) monitorService(ctx context.Context) error {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("stack", string(debug.Stack())).Msg("Monitor avira")
			}
		}()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			n := time.Now().Unix()
			pre := s.HeatBeat.Load()
			// 10分钟都没有使用了，说明：
			// 可能1：没有开启动深度扫描
			// 可能2：虽然开启了深度扫描，但是最近没有扫描任务
			if pre > 0 && n-pre > 10*60 {
				s.TaskWG.Wait()

				if s.HeatBeat.Load() != pre {
					continue
				}
				if err := s.AviraServer.KillServer(); err != nil {
					s.Log.Err(err).Msg("AviraServer KillServer")
					continue
				}
				s.HeatBeat.Store(0)
				s.Log.Info().Msg("service has not been used in the last 10 minutes,AviraServer KillServer")
			}
		}
	}()
	return nil
}

var (
	ErrScanTimeout = fmt.Errorf("scan time out")
)
