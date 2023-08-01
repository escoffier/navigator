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
	"gitlab.com/piccolo_su/vegeta/pkg/avira"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var aviraSrv *AviraSrv

type AviraSrv struct {
	MalwareEnginName string
	EnginChan        chan *avira.SavClient
	Engin            *avira.SavClient
	WorkingVersion   imagesecModel.DBVersionInfo
	LastVersion      imagesecModel.DBVersionInfo
	LastDBPathInfo   imagesecModel.DBPathInfo
	WorkDBPathInfo   imagesecModel.DBPathInfo
	AviraServer      *avira.SavServer
	TaskWG           sync.WaitGroup // 任务执行情况
	ServerAddr       string
}

func NewSavServer() (*AviraSrv, error) {
	if aviraSrv != nil {
		return aviraSrv, nil
	}
	srv := &AviraSrv{
		ServerAddr:       fmt.Sprintf("tcp:127.0.0.1:%d", avira.DefaultSavApiListenAddr),
		MalwareEnginName: consts.AviraName,
		EnginChan:        make(chan *avira.SavClient),
		WorkingVersion:   imagesecModel.DBVersionInfo{},
		LastVersion:      imagesecModel.DBVersionInfo{},
		LastDBPathInfo:   types.GetAviraDBPathInfo(),
		WorkDBPathInfo:   types.GetAviraDBPathInfo(),
		TaskWG:           sync.WaitGroup{},
	}

	if err := srv.generateVersionFromWorkPath(); err != nil {
		return nil, err
	}

	srv.WorkingVersion = srv.getVersionFromFile(context.Background(), srv.WorkDBPathInfo.WorkVersionFilename)

	if err := os.MkdirAll(srv.WorkDBPathInfo.UpdatePath, os.ModePerm); err != nil {
		return nil, err
	}

	srv.AviraServer = NewSavEngin()

	srv.GenEnginChan(context.Background())
	aviraSrv = srv

	return aviraSrv, nil
}

func NewAviraUpdateSrv() *AviraSrv {
	srv := &AviraSrv{
		MalwareEnginName: consts.AviraName,
		WorkDBPathInfo:   types.GetAviraDBPathInfo(),
	}

	srv.WorkingVersion = srv.getVersionFromFile(context.Background(), srv.WorkDBPathInfo.WorkVersionFilename)

	return srv
}

func NewSavEngin() *avira.SavServer {
	savServer := avira.NewSavServer(avira.WithListenPort(avira.DefaultSavApiListenAddr))
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		savServer.StartServer()
		logging.Get().Info().Str("module", "imagescan").Msg("start avira server succeed")
	}()

	return savServer
}

func (s *AviraSrv) GenEnginChan(ctx context.Context) {
	s.getEnginBackground(ctx)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("panic recover GenEnginChan")
			}
		}()

		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			if lastPath, err := s.getLastUpdatePath(ctx); err == nil {
				verPath := path.Join(s.LastDBPathInfo.UpdatePath, lastPath, s.MalwareEnginName, consts.VersionStr)
				s.LastVersion = s.getVersionFromFile(ctx, verPath)
				s.LastDBPathInfo.UpdateZipFilename = path.Join(s.LastDBPathInfo.UpdatePath, fmt.Sprintf("%s.zip", lastPath))
				s.LastDBPathInfo.UpdateUnZipPath = path.Join(s.LastDBPathInfo.UpdatePath, lastPath)
			}

			if !s.needUpdate(ctx) {
				logging.Get().Debug().Str("module", "imagescan").Interface("LastDBPathInfo", s.LastDBPathInfo).Msg("GenEnginChan do not need update db")
				if s.Engin == nil {
					client, err := avira.NewSavClient(s.ServerAddr)
					if err != nil {
						logging.Get().Err(err).Str("module", "imagescan").Msg("NewSavClient")
						<-ticker.C
						continue
					}
					s.Engin = client
				}

				s.EnginChan <- s.Engin
				continue
			}

			logging.Get().Debug().Str("module", "imagescan").Interface("LastDBPathInfo", s.LastDBPathInfo).Msg("GenEnginChan need update db")

			s.TaskWG.Wait() // 等待任务执行完成

			if err := s.AviraServer.KillServer(); err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("GenEnginChan Close AviraServer")
				<-ticker.C
				continue
			}

			logging.Get().Debug().Str("module", "imagescan").Msg("GenEnginChan killed server")

			// copy all db files
			osCMD := exec.Command("cp", "-rf", s.getUpdateClamavPath(ctx), s.WorkDBPathInfo.WorkPath)
			logging.Get().Info().Str("module", "imagescan").Strs("cmd", osCMD.Args).Msg("GenEnginChan copy db file")

			if err := osCMD.Run(); err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Strs("cmd", osCMD.Args).Msg("GenEnginChan copy db file")
				<-ticker.C
				continue
			}
			// restart server

			s.AviraServer = NewSavEngin()
			s.Engin = nil

			logging.Get().Debug().Str("module", "imagescan").Interface("LastVersion", s.LastVersion).Msg("GenEnginChan restart server")

			s.WorkingVersion = s.LastVersion

			// 删除临时文件
			_ = os.RemoveAll(s.LastDBPathInfo.UpdateUnZipPath)
			// 向子集群及和节点全部发送完之后才能删除
			// _ = os.RemoveAll(s.LastDBPathInfo.UpdateZipFilename)
			logging.Get().Debug().Str("module", "imagescan").Interface("LastDBPathInfo", s.LastDBPathInfo).Msg("GenEnginChan")
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

func (s *AviraSrv) ScanFile(_ context.Context, filename string) ([]imagesecModel.Malware, error) {

	engin := <-s.EnginChan

	s.TaskWG.Add(1)
	defer s.TaskWG.Done()

	file, err := engin.ScanFile(filename)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("MalwareEnginName", s.MalwareEnginName).Msg("ScanFile")
		return nil, err
	}
	res := make([]imagesecModel.Malware, 0)
	for i := range file {
		res = append(res, imagesecModel.Malware{
			Name:        file[i].Name,
			Filename:    filename,
			MalwareType: file[i].Type,
			Description: file[i].Desc,
		})
	}

	return res, nil
}

// 当用户在界面上更新病毒库后，只有当获取扫描 engin 时才会去加载新的病毒库，如果一直没有扫描任务则一直不会加载病毒库
func (s *AviraSrv) getEnginBackground(_ context.Context) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("panic recover GenEnginChan")
			}
		}()

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			<-s.EnginChan
		}
	}()
}

func (s *AviraSrv) getVersionFromFile(ctx context.Context, filename string) imagesecModel.DBVersionInfo {
	if !util.FileExists(s.WorkDBPathInfo.WorkVersionFilename) {
		return imagesecModel.DBVersionInfo{}
	}

	fileContent, err := os.ReadFile(filename)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("filename", filename).Msg("getVersionFromFile")
		return imagesecModel.DBVersionInfo{}
	}
	t := AviraVersion{}
	if err := json.Unmarshal(fileContent, &t); err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("filename", filename).Msg("getVersionFromFile")
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
		logging.Get().Err(err).Str("module", "imagescan").Msg("UpdateDB")
		return nil, err
	}

	if err := util.Unzip(pa.UpdateZipFilename, pa.UpdateUnZipPath, consts.DBPassword); err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("ClamavSrv not zip file")
		return nil, err
	}

	pa.UpdateVersionFilename = path.Join(pa.UpdateUnZipPath, s.MalwareEnginName, consts.VersionStr)

	version := s.getVersionFromFile(ctx, pa.UpdateVersionFilename)

	logging.Get().Info().Str("module", "imagescan").Str("dbType", param.DbType).Str("dbVersion", version.Version).
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
		logging.Get().Err(err).Str("module", "imagescan").Msg("get avira version")
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
		logging.Get().Err(err).Str("module", "imagescan").Str("path", s.LastDBPathInfo.UpdatePath).Msg("getVersionLastVersion")
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
		logging.Get().Err(err).Str("module", "imagescan").Msg("generateVersionFromWorkPath")
		return err
	}
	md5Str, err := util.Md5FromFile(s.WorkDBPathInfo.BinFilename)

	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("generateVersionFromWorkPath Md5FromFile")
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
		logging.Get().Err(err).Str("module", "imagescan").Msg("generateVersionFromWorkPath Marshal")
		return err
	}
	err = os.WriteFile(s.WorkDBPathInfo.WorkVersionFilename, verByte, 0600)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("generateVersionFromWorkPath do not write version file")
		return err
	}
	return nil
}

func (s *AviraSrv) getLastUpdatePath(_ context.Context) (string, error) {
	dir, err := os.ReadDir(s.LastDBPathInfo.UpdatePath)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("path", s.LastDBPathInfo.UpdatePath).Msg("getVersionLastVersion")
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
		logging.Get().Info().Str("module", "imagescan").Msg("not find last db path")
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
