package scanTrivy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/analyzer"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy-db/pkg/db"
	dbtypes "scm.tensorsecurity.cn/tensorsecurity-rd/trivy-db/pkg/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/commands/artifact"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/commands/option"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/types"

	vulnmatch "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-match"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	imagesecType "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (s *TrivySrv) getUpdatePath() string {
	updatePath := filepath.Join(s.VulnRootPath, "update")
	if err := util.MkdirIfNotExist(updatePath, false); err != nil {
		return ""
	}

	return updatePath
}

// 获取当前 trivy 扫描器的漏洞目录
func (s *TrivySrv) vulnDbPath() string {
	dbPath := filepath.Join(s.VulnRootPath, "db")
	if err := util.MkdirIfNotExist(dbPath, false); err != nil {
		return ""
	}
	return dbPath
}

func (s *TrivySrv) getAllUpdatePath(ctx context.Context) []string {
	ans := make([]string, 0)

	updatePath := s.getUpdatePath()
	dir, err := os.ReadDir(updatePath)
	if err != nil {
		s.Log.Err(err).Str("updatePath", updatePath).Msg("getLastUpdatePath")
		return ans
	}
	dirs := make([]int, 0)

	for _, fi := range dir {
		if !fi.IsDir() {
			continue
		}
		dirN := fi.Name()
		split := strings.Split(dirN, string(os.PathSeparator))
		if len(split) == 0 || split[0] == "" {
			continue
		}

		if tm, err := strconv.Atoi(split[len(split)-1]); err == nil && tm > 0 {
			dirs = append(dirs, tm)
		}
	}
	sort.Ints(dirs)
	for i := range dirs {
		ans = append(ans, filepath.Join(s.getUpdatePath(), fmt.Sprintf("%d", dirs[i])))
	}
	return ans
}

func (s *TrivySrv) getLastUpdatePath(ctx context.Context) string {
	path := s.getAllUpdatePath(ctx)
	if len(path) > 0 {
		return path[len(path)-1]
	}
	return ""
}

func (s *TrivySrv) getVersionFromFile(ctx context.Context, filename string) VulnDBVersion {
	blank := VulnDBVersion{}
	if !util.FileExists(filename) {
		return blank
	}

	fileContent, err := os.ReadFile(filename)
	if err != nil {
		s.Log.Err(err).Str("filename", filename).Msg("getVersionFromFile")
		return blank
	}
	t := VulnDBVersion{}
	if err := json.Unmarshal(fileContent, &t); err != nil {
		s.Log.Err(err).Str("filename", filename).Msg("getVersionFromFile")
		return blank
	}
	return t
}

func (s *TrivySrv) needUpdate(ctx context.Context) bool {
	if s.LastVersion.TrivyVersion.Version == "" {
		return false
	}

	if s.WorkingVersion.TrivyVersion.Version == s.LastVersion.TrivyVersion.Version &&
		s.WorkingVersion.TrivyVersion.Hash == s.LastVersion.TrivyVersion.Hash {
		return false
	}

	return true
}

func (s *TrivySrv) checkVulnHash(ver VulnDBVersion, path string) bool {
	trivyHash, err := util.Md5FromFile(filepath.Join(path, "trivy.db"))
	if err != nil {
		logging.GetLogger().Err(err).Msg("get trivyDB hash failure")
		return false
	}

	customHash, err := util.Md5FromFile(filepath.Join(path, "custom.db"))
	if err != nil {
		logging.GetLogger().Err(err).Msg("get trivyDB hash failure")
		return false
	}
	if trivyHash != ver.TrivyVersion.Hash {
		return false
	}
	if customHash != ver.CustomDBVersion.Hash {
		return false
	}

	return false
}

// deployment 中写的 path
func (s *TrivySrv) GetInitTrivyPath() string {
	p := fmt.Sprintf("%s/trivy/", s.PvcPath)
	return strings.ReplaceAll(p, "//", "/")
}

func (s *TrivySrv) compareVersion(ver1, ver2 VulnDBVersion) bool {
	if ver1.TrivyVersion.Version < ver2.TrivyVersion.Version {
		return false
	}
	if ver1.CustomDBVersion.Version < ver2.CustomDBVersion.Version {
		return false
	}
	return true
}

func (s *TrivySrv) genVulnMatcherChan(ctx context.Context) {

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("panic recover GenEnginChan")
			}
		}()

		ticker := time.NewTicker(time.Microsecond)
		defer ticker.Stop()

		for {
			<-ticker.C
			if !s.BoltDbOpened {
				s.Log.Info().Msg("genVulnMatcherChan BoltDb not opened,open it ")
				s.TaskWG.Wait()

				// 重新实例化db对象
				if err := db.Init(s.VulnRootPath); err != nil {
					time.Sleep(time.Second * 10)
					// fixme 没有启动成功，说明原 vulnDB 文件有错误，应该删除重新使用初始化 DB
					s.Log.Err(err).Msg("InitBoltDB")
					continue
				}
				customDB, err := OpenBoltDB(filepath.Join(s.vulnDbPath(), CustomDB))
				if err != nil {
					s.Log.Err(err).Msg("Open custom DB")
					continue
				}
				s.CustomDB = customDB
				s.BoltDbOpened = true
				s.WorkingVersion = s.getVersionFromFile(ctx, filepath.Join(s.vulnDbPath(), consts.VersionStr))
				s.Log.Info().Msg("genVulnMatcherChan open bolt db success")
			}

			lastPath := s.getLastUpdatePath(ctx)
			if lastPath != "" {
				s.LastVersion = s.getVersionFromFile(ctx, filepath.Join(lastPath, consts.VersionStr))
			}

			s.Log.Debug().Interface("LastVersion", s.LastVersion).Interface("WorkingVersion", s.WorkingVersion).
				Msg("genVulnMatcherChan get version")

			if s.needUpdate(ctx) {
				s.Log.Info().Msg("need update vuln db")
				s.TaskWG.Wait() // 等待任务执行完成
				// 关闭原 boltDB,如果没有打开，也不会报错
				if err := db.Close(); err != nil {
					time.Sleep(time.Second * 10)
					s.Log.Err(err).Msg("Close trivy BoltDB")
					continue
				}
				// 再关闭 custom db
				if s.CustomDB != nil {
					if err := s.CustomDB.Close(); err != nil {
						time.Sleep(time.Second * 10)
						s.Log.Err(err).Msg("Close CustomDB")
						continue
					}
				}
				s.BoltDbOpened = false
				// 复制文件
				pre := fmt.Sprintf("%s/*", s.getLastUpdatePath(ctx))

				if err := s.copyInitBoltDB(ctx, s.getLastUpdatePath(ctx)); err != nil {
					s.Log.Err(err).Str("updatePath", pre).Msg("copyInitBoltDB")
					time.Sleep(time.Second * 10)
					continue
				}
				// 重新实例化db对象
				if err := db.Init(s.VulnRootPath); err != nil {
					time.Sleep(time.Second * 10)
					// fixme 没有启动成功，说明原 vulnDB 文件有错误，应该删除重新使用初始化 DB
					// 这种情况可能需要运维介入了
					s.Log.Err(err).Msg("InitBoltDB")
					continue
				}
				customDB, err := OpenBoltDB(filepath.Join(s.vulnDbPath(), CustomDB))
				if err != nil {
					s.Log.Err(err).Msg("genVulnMatcherChan Open custom DB")
					continue
				}
				s.CustomDB = customDB

				s.BoltDbOpened = true
				s.WorkingVersion = s.LastVersion
				s.Log.Info().Msg("genVulnMatcherChan update vuln db finished")
			}

			matcher, err := vulnmatch.NewMatcher()
			if err != nil {
				s.Log.Err(err).Msg("NewMatcher")
				continue
			}
			s.MatcherChan <- matcher
			s.Log.Debug().Msg("genVulnMatcherChan send vuln matcher")
		}
	}()
}

func (s *TrivySrv) copyInitBoltDB(ctx context.Context, prePath string) error {
	workPath := s.vulnDbPath()
	// initPath := s.GetInitTrivyPath()

	files := []string{"custom.db", "trivy.db", "version"}

	for _, fi := range files {
		// 先删除当前使用的db
		_ = os.Remove(filepath.Join(workPath, fi))
		// 再复制需要的文件
		if err := scannerUtils.CopyFile(filepath.Join(prePath, fi), filepath.Join(workPath, fi)); err != nil {
			s.Log.Err(err).Str("boltdb", fi).Msg("copy vuln db")
			return fmt.Errorf("copy vuln db :%s", fi)
		}
		s.Log.Info().Str("boltdb", fi).Msg("copyInitBoltDB")
	}
	return nil
}

func (s *TrivySrv) GetMatcher(ctx context.Context) (*vulnmatch.Matcher, error) {
	timeout, cancelFunc := context.WithTimeout(ctx, time.Duration(2)*time.Second)
	defer cancelFunc()
	for {
		select {
		case <-timeout.Done():
			return nil, fmt.Errorf("get matcher timeout")
		case cli := <-s.MatcherChan:
			return cli, nil
		}
	}
}

func (s *TrivySrv) getCnnvdFromBolt(vulnName string) (*imagesecType.CnnvdInfo, error) {
	cnnvdRes := imagesecType.CnnvdInfo{}
	err := s.CustomDB.View(func(tx *bolt.Tx) error {
		var err error
		cnvdBucket := tx.Bucket([]byte("cnnvd"))
		if cnvdBucket == nil {
			return fmt.Errorf("not get cnnvd bucket")
		}
		cnvdBytes := cnvdBucket.Get([]byte(vulnName))
		if len(cnvdBytes) == 0 {
			return fmt.Errorf("not get %s cnnvd data", vulnName)
		}

		err = json.Unmarshal(cnvdBytes, &cnnvdRes)
		if err != nil {
			return err
		}
		return nil
	})
	return &cnnvdRes, err
}

func (s *TrivySrv) getCnvdFromBolt(vulnName string) ([]imagesecType.CnvdInfo, error) {
	cnvdRes := make([]imagesecType.CnvdInfo, 0)
	err := s.CustomDB.View(func(tx *bolt.Tx) error {
		var err error
		cnvdBucket := tx.Bucket([]byte("cnvd"))
		if cnvdBucket == nil {
			return fmt.Errorf("not get cnvd bucket")
		}
		cnvdBytes := cnvdBucket.Get([]byte(vulnName))
		if len(cnvdBytes) == 0 {
			return fmt.Errorf("not get %s cnvd data", vulnName)
		}

		err = json.Unmarshal(cnvdBytes, &cnvdRes)
		if err != nil {
			return err
		}
		return nil
	})
	return cnvdRes, err
}

func OpenBoltDB(path string) (*bolt.DB, error) {
	options := bolt.Options{
		Timeout:  time.Second * 10,
		ReadOnly: true,
	}
	options.Timeout = time.Second * 15
	boltDB, err := bolt.Open(path, 0600, &options)
	if err != nil {
		return nil, err
	}
	return boltDB, nil
}

type VulnDBVersion struct {
	CompressDBVersion string `json:"compressDBVersion"`
	TrivyVersion      struct {
		Version string `json:"version"`
		Comment string `json:"comment"`
		Hash    string `json:"hash"`
	} `json:"trivyVersion"`
	CustomDBVersion struct {
		Version string `json:"version"`
		Comment string `json:"comment"`
		Hash    string `json:"hash"`
	} `json:"customDBVersion"`
	UpdateTime int64 `json:"updateTime"`
}

func NewTrivyScanOptions(image string) artifact.Option {
	opt := artifact.Option{
		GlobalOption:      option.GlobalOption{},
		DisabledAnalyzers: analyzer.TypeLockIac,
		ArtifactOption: option.ArtifactOption{
			Target: image,
		},
		DBOption:    option.DBOption{},
		ImageOption: option.ImageOption{},
		ReportOption: option.ReportOption{
			Format:         "table",
			IgnoreFile:     ".trivyignore",
			VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
			SecurityChecks: []types.SecurityCheck{types.SecurityCheckVulnerability},
			Severities: []dbtypes.Severity{
				dbtypes.SeverityUnknown,
				dbtypes.SeverityLow,
				dbtypes.SeverityMedium,
				dbtypes.SeverityHigh,
				dbtypes.SeverityCritical,
			},
		},
		CacheOption:  option.CacheOption{},
		ConfigOption: option.ConfigOption{},
	}

	opt.ImageOption.ListAllPkgs = true
	opt.OnlyScanPkgs = true
	opt.ArtifactOption.OfflineScan = true

	offline := os.Getenv("OFFLINE_SCAN")
	if offline != "" {
		opt.ArtifactOption.OfflineScan = true
	}
	onlyScanPkgs := os.Getenv("ONLY_SCAN_PKGS")
	if onlyScanPkgs == consts.FalseString {
		opt.OnlyScanPkgs = false
	}
	return opt
}
