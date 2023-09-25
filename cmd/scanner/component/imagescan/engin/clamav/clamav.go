package clamavengin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"sync"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ClamavSrv struct {
	MalwareEnginName string
	EnginChan        chan *ClamavEngin
	ClamavEngin      *ClamavEngin
	WorkingVersion   imagesecModel.DBVersionInfo
	LastVersion      imagesecModel.DBVersionInfo
	LastDBPathInfo   imagesecModel.DBPathInfo
	WorkDBPathInfo   imagesecModel.DBPathInfo
	TaskWG           sync.WaitGroup // 任务执行情况
}

func NewClamavUpdateSrv() *ClamavSrv {
	srv := &ClamavSrv{
		MalwareEnginName: consts.ClamavName,
		EnginChan:        make(chan *ClamavEngin),
		WorkDBPathInfo:   types.GetClamavDBPathInfo(),
	}

	srv.WorkingVersion = srv.getVersionFromFile(context.Background(), srv.WorkDBPathInfo.WorkVersionFilename)

	return srv
}

func NewClamavSrv() (*ClamavSrv, error) {
	engin, err := GetClamavEngin()
	if err != nil {
		return nil, err
	}
	srv := &ClamavSrv{
		MalwareEnginName: consts.ClamavName,
		EnginChan:        make(chan *ClamavEngin),
		ClamavEngin:      engin,
		WorkingVersion:   imagesecModel.DBVersionInfo{},
		LastVersion:      imagesecModel.DBVersionInfo{},
		LastDBPathInfo:   types.GetClamavDBPathInfo(),
		WorkDBPathInfo:   types.GetClamavDBPathInfo(),
		TaskWG:           sync.WaitGroup{},
	}

	srv.WorkingVersion = srv.getVersionFromFile(context.Background(), srv.WorkDBPathInfo.WorkVersionFilename)

	if err := os.MkdirAll(srv.WorkDBPathInfo.UpdatePath, os.ModePerm); err != nil {
		return nil, err
	}

	if err := srv.ClamavEngin.ReloadDB(srv.WorkDBPathInfo.WorkPath); err != nil {
		return nil, err
	}

	srv.GenEnginChan(context.Background())

	return srv, nil
}

func (s *ClamavSrv) GenEnginChan(ctx context.Context) {
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

			if !s.needUpdateDB(ctx) {
				logging.Get().Debug().Str("module", "imagescan").Interface("LastDBPathInfo", s.LastDBPathInfo).Msg("GenEnginChan do not need update db")
				s.EnginChan <- s.ClamavEngin
				continue
			}

			logging.Get().Debug().Str("module", "imagescan").Interface("LastDBPathInfo", s.LastDBPathInfo).Msg("GenEnginChan need update db")

			s.TaskWG.Wait() // 等待任务执行完成

			if err := s.ClamavEngin.CloseClEngine(); err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("CloseClEngine")
				<-ticker.C
				continue
			}

			logging.Get().Debug().Str("module", "imagescan").Msg("GenEnginChan close engin server")

			osCMD := exec.Command("cp", "-rf", s.getUpdateClamavPath(ctx), s.WorkDBPathInfo.WorkPath)
			logging.Get().Info().Str("module", "imagescan").Strs("cmd", osCMD.Args).Msg("GenEnginChan copy db file")

			if err := osCMD.Run(); err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Strs("cmd", osCMD.Args).Msg("GenEnginChan copy db file")
				<-ticker.C
				continue
			}

			engin, err := GetClamavEngin()

			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("GenEnginChan GetClamavEngin")
				<-ticker.C
				continue
			}

			logging.Get().Debug().Str("module", "imagescan").Msg("GenEnginChan GetClamavEngin")
			s.ClamavEngin = engin

			if err := s.ClamavEngin.ReloadDB(s.WorkDBPathInfo.WorkPath); err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Str("MalwareEnginName", s.MalwareEnginName).Msg("ReloadDB")
				<-ticker.C
				continue
			}
			s.WorkingVersion = s.LastVersion
			// 删除临时文件
			_ = os.RemoveAll(s.LastDBPathInfo.UpdateUnZipPath)
			// _ = os.RemoveAll(s.LastDBPathInfo.UpdateZipFilename)
			logging.Get().Debug().Str("module", "imagescan").Interface("lastDBPathInfo", s.LastVersion).Msg("GenEnginChan ReloadDB")
		}
	}()
}

// 当用户在界面上更新病毒库后，只有当获取扫描 engin 时才会去加载新的病毒库，如果一直没有扫描任务则一直不会加载病毒库
func (s *ClamavSrv) getEnginBackground(_ context.Context) {
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

func (s *ClamavSrv) ScanFile(_ context.Context, filename string) ([]imagesecModel.Malware, error) {
	engin := <-s.EnginChan

	s.TaskWG.Add(1)
	defer s.TaskWG.Done()

	file, err := engin.ScanFile(filename)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("MalwareEnginName", s.MalwareEnginName).Msg("ScanFile")
		return nil, err
	}
	res := make([]imagesecModel.Malware, 0)
	res = append(res, imagesecModel.Malware{Name: file, Filename: filename})

	return res, nil
}

func (s *ClamavSrv) UpdateDB(ctx context.Context, param imagesecModel.UpdateDbParam) (*imagesecModel.ScanDbMeta, error) {

	pa := types.GetClamavDBPathInfo()
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

	pa.UpdateVersionFilename = s.getUpdateVersionFilename(ctx, pa)

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
			DBPathInfo:    pa,
		},
	}

	return dbMeta, nil
}

func (s *ClamavSrv) getUpdateVersionFilename(_ context.Context, pa imagesecModel.DBPathInfo) string {
	if pa.UpdateUnZipPath == "" {
		return ""
	}
	return pa.UpdateUnZipPath + "/" + consts.ClamavName + "/" + consts.VersionStr
}

func (s *ClamavSrv) getUpdateClamavPath(_ context.Context) string {
	if s.LastDBPathInfo.UpdateUnZipPath == "" {
		return ""
	}
	return path.Join(s.LastDBPathInfo.UpdateUnZipPath, s.MalwareEnginName)
}

func (s *ClamavSrv) getVersionFromFile(ctx context.Context, filename string) imagesecModel.DBVersionInfo {
	fileContent, err := os.ReadFile(filename)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("filename", filename).Msg("GetVersion")
		return imagesecModel.DBVersionInfo{}
	}
	t := ClamavVersion{}
	if err := json.Unmarshal(fileContent, &t); err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("filename", filename).Msg("GetVersion")
		return imagesecModel.DBVersionInfo{}
	}
	vv := imagesecModel.DBVersionInfo{
		DBType:   consts.ClamavName,
		Version:  t.ClamavVersion.Version,
		UpdateAt: t.UpdateTime,
		Comment:  t.ClamavVersion.Comment,
		Hash:     t.ClamavVersion.Hash,
	}
	return vv
}

func (s *ClamavSrv) needUpdateDB(ctx context.Context) bool {
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

func (s *ClamavSrv) getLastUpdatePath(_ context.Context) (string, error) {
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

type ClamavVersion struct {
	CompressDBVersion string `json:"compressDBVersion"`
	ClamavVersion     struct {
		Version string `json:"version"`
		Comment string `json:"comment"`
		Hash    string `json:"hash"`
	} `json:"ClamavVersion"`
	UpdateTime int64 `json:"updateTime"`
}
