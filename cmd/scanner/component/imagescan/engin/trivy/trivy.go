package scanTrivy

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/go-redis/redis/v8"
	"github.com/google/go-containerregistry/pkg/name"
	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy"
	trivylog "scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/log"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/global"
	vulnmatch "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-match"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type TrivySrv struct {
	PvcPath        string // pvc path,default:/root/alldb
	MatcherChan    chan *vulnmatch.Matcher
	TrivyScanner   *trivy.Scanner
	RedisCli       *redis.Client
	CachePath      string        // 如果 trivy用文件缓存扫描结果，就使用这个参数
	WorkingVersion VulnDBVersion // 正在使用的版本号
	BoltDbOpened   bool
	CustomDB       *bolt.DB // custome db 的实例
	LastVersion    VulnDBVersion
	VulnRootPath   string          // 漏洞库，初次启动需要复制原文件到该目录下 /root/alldb/vuln/
	ImageCacheURL  string          // 仓库镜像扫描时的缓存路径
	TaskWG         *sync.WaitGroup // 任务执行情况
	TimeoutSec     int64           // 超时时间,单位：秒
	Log            *scannerUtils.LogEvent
}

// 漏洞扫描只会在主集群更新
func (s *TrivySrv) UpdateDB(ctx context.Context, param imagesecModel.UpdateDbParam) (*imagesecModel.ScanConfigDB, error) {
	if !scannerUtils.MainCluster() {
		return nil, fmt.Errorf("not in mian cluster")
	}
	s.TaskWG.Add(1)
	defer s.TaskWG.Done()

	updatePath := s.getUpdatePath()

	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())

	zipFilename := path.Join(updatePath, timestamp+".zip")
	unZipPath := path.Join(updatePath, timestamp)

	s.Log.Info().Str("zipFilename", zipFilename).Str("unZipPath", unZipPath).Msg("UpdateDB")

	if err := os.WriteFile(zipFilename, param.Data, os.ModePerm); err != nil {
		s.Log.Err(err).Msg("UpdateDB")
		_ = os.RemoveAll(zipFilename)
		_ = os.RemoveAll(unZipPath)
		return nil, err
	}

	if err := scannerUtils.UnzipDBFile(zipFilename, unZipPath, consts.DBPassword); err != nil {
		s.Log.Err(err).Msg("not zip file")
		_ = os.RemoveAll(zipFilename)
		_ = os.RemoveAll(unZipPath)
		return nil, err
	}
	s.Log.Info().Str("zipFilename", zipFilename).Str("unZipPath", unZipPath).Msg("UpdateDB UnzipDBFile")
	// 验证
	ver := s.getVersionFromFile(ctx, filepath.Join(unZipPath, consts.VersionStr))
	if ver.TrivyVersion.Version == "" || ver.CustomDBVersion.Version == "" {
		_ = os.RemoveAll(zipFilename)
		_ = os.RemoveAll(unZipPath)
		return nil, fmt.Errorf("not get db version")
	}
	s.Log.Info().Interface("version", ver).Msg("UpdateDB version")

	// check hash
	trivyHash := scannerUtils.GetFileMd5(filepath.Join(unZipPath, consts.TrivyDbName))
	customDbHash := scannerUtils.GetFileMd5(filepath.Join(unZipPath, consts.CustomDbName))
	if ver.TrivyVersion.Hash != trivyHash || ver.CustomDBVersion.Hash != customDbHash {
		_ = os.RemoveAll(zipFilename)
		_ = os.RemoveAll(unZipPath)
		return nil, fmt.Errorf("db hash not correct")
	}

	s.Log.Info().Str("zipFilename", zipFilename).Str("unZipPath", unZipPath).Msg("UpdateDB checked hash")
	// 打开 db 试试
	trivyDB, err := OpenBoltDB(filepath.Join(unZipPath, consts.TrivyDbName))
	if err != nil {
		_ = os.RemoveAll(zipFilename)
		_ = os.RemoveAll(unZipPath)
		return nil, fmt.Errorf("can not open vuln db")
	}

	if err := trivyDB.Close(); err != nil {
		_ = os.RemoveAll(zipFilename)
		_ = os.RemoveAll(unZipPath)
		return nil, fmt.Errorf("can not close vuln db")
	}

	cusDB, err := OpenBoltDB(filepath.Join(unZipPath, consts.TrivyDbName))
	if err != nil {
		_ = os.RemoveAll(zipFilename)
		_ = os.RemoveAll(unZipPath)
		return nil, fmt.Errorf("can not open vuln db")
	}
	_ = cusDB.Close()

	s.Log.Info().Str("zipFilename", zipFilename).Str("unZipPath", unZipPath).Msg("UpdateDB checked bolt db")
	// 删除zip 包
	_ = os.Remove(zipFilename)

	// 删除本次更新之后，删除之前所有的更新文件,防止文件堆积
	all := s.getAllUpdatePath(ctx)

	s.Log.Info().Strs("AllUpdatePath", all).Msg("getAllUpdatePath")

	for i := len(all) - 2; i >= 0; i-- {
		s.Log.Info().Str("deletedPath", all[i]).Msg("UpdateDB")
		_ = os.RemoveAll(all[i])
	}

	s.Log.Info().Str("zipFilename", zipFilename).Str("unZipPath", unZipPath).Msg("UpdateDB delete expired vuln db")

	ans := &imagesecModel.ScanConfigDB{
		DBVersion: ver.CompressDBVersion,
		DBType:    consts.TrivyName,
		DBMd5:     ver.TrivyVersion.Hash,
		DBMeta: imagesecModel.DBMeta{
			DBVersion: ver.TrivyVersion.Version,
			DBComment: ver.TrivyVersion.Comment,
			DBHash:    ver.TrivyVersion.Hash,
		},
		Updater: param.Updater,
	}

	return ans, nil
}

// 扫描
func (s *TrivySrv) ImageScan(ctx context.Context, prep *imagesecTypes.PrepareScan) []imagesecTypes.ScanJobResult {
	// 如果需要统一节点镜像的扫描时再做
	start := time.Now().Unix()
	s.logScanStart(prep)
	defer s.logScanEnd(start, prep)

	result := make([]imagesecTypes.ScanJobResult, 0)
	res := imagesecTypes.ScanJobResult{
		DBVersion: s.WorkingVersion.TrivyVersion.Version,
		Layer:     prep.ImageManifest.ImageDigest,
		Issue:     imagesecModel.VulnCacheData,
	}
	// 检测缓存
	if prep.Subtask.VulnCache.In(prep.ImageManifest.ImageDigest) {
		res.InCache = true
		result = append(result, res)
		return result
	}
	res.Scanned = true

	imageName := prep.Subtask.RegImageMeta.ImageName()
	imageName, err := s.changCacheUrl(imageName)

	if err != nil {
		s.Log.Err(err).Str("subtask", prep.Subtask.LogStr()).Msg("changCacheUrl")
		res.Errors = append(res.Errors, err)
		result = append(result, res)
		return result
	}

	opt := NewTrivyScanOptions(imageName)
	trivyRes, err := s.TrivyScanner.Scan(ctx, imageName, opt)
	if err != nil {
		s.Log.Err(err).Str("subtask", prep.Subtask.LogStr()).Msg("Scan")
		res.Errors = append(res.Errors, err)
		result = append(result, res)
		return result
	}

	art := make([]ftypes.ArtifactDetail, 0)
	for i := range trivyRes.Results {
		art = append(art, trivyRes.Results[i].Artifact)
	}
	res.OriginArtifact = art
	result = append(result, res)
	return result
}

// 匹配漏洞
func (s *TrivySrv) MatchVuln(ctx context.Context, artifactDetail ftypes.ArtifactDetail) (report.Results, error) {
	s.TaskWG.Add(1)
	defer s.TaskWG.Done()
	matcher, err := s.GetMatcher(ctx)
	if err != nil {
		return nil, err
	}
	rp, err := matcher.MatchVulnerability(artifactDetail)

	return rp, err
}

func (s *TrivySrv) AddDetailVuln(ctx context.Context, vuln *imagesecModel.Vuln) *imagesecModel.Vuln {
	if vuln == nil || s.CustomDB == nil {
		return vuln
	}

	s.TaskWG.Add(1)
	defer s.TaskWG.Done()
	_, err := s.GetMatcher(ctx)
	if err != nil {
		return vuln
	}

	cnnvdData, err := s.getCnnvdFromBolt(vuln.Name)
	if err != nil {
		s.Log.Debug().Str("error", err.Error()).Str("vulnID", vuln.Name).Msg("getCnnvdFromBolt not get cnnvd")
	}
	cnvdData, err := s.getCnvdFromBolt(vuln.Name)
	if err != nil {
		s.Log.Debug().Str("error", err.Error()).Str("vulnID", vuln.Name).Msg("getCnvdFromBolt not get cnvd")
	}

	if cnnvdData != nil {
		vuln.CnnvdName = cnnvdData.Number
		vuln.CnnvdFixSuggestion = cnnvdData.FixSuggestion
		if len(vuln.References) == 0 {
			vuln.References = make([]string, 0)
		}
		if cnnvdData.RefLink != "" {
			vuln.References = append(vuln.References, cnnvdData.RefLink)
		}
	}
	if len(cnvdData) > 0 {
		vuln.CnvdTitle = cnvdData[0].Title
		vuln.DescriptionZh = cnvdData[0].Description
	}
	s.Log.Debug().Str("vulnID", vuln.Name).Msg("AddDetailVuln")
	return vuln
}

func (s *TrivySrv) GetWorkVersion(ctx context.Context) (*imagesecModel.ScanConfigDB, error) {
	db := &imagesecModel.ScanConfigDB{
		DBVersion: s.WorkingVersion.TrivyVersion.Version,
		DBType:    consts.TrivyName,
		DBMd5:     s.WorkingVersion.TrivyVersion.Hash,
		DBMeta: imagesecModel.DBMeta{
			DBVersion: s.WorkingVersion.TrivyVersion.Version,
			DBComment: s.WorkingVersion.TrivyVersion.Comment,
			DBHash:    s.WorkingVersion.TrivyVersion.Hash,
		},
	}

	return db, nil
}

type SingleTrivySrv struct {
	TrivySrv *TrivySrv
	WG       sync.Locker
}

// 这样才保险
func init() {
	singleMeta = &SingleTrivySrv{
		TrivySrv: nil,
		WG:       &sync.Mutex{},
	}
}

var singleMeta *SingleTrivySrv

// 单例
func NewTrivySrv(opts ...Option) (*TrivySrv, error) {
	singleMeta.WG.Lock()
	defer singleMeta.WG.Unlock()
	if singleMeta.TrivySrv != nil {
		return singleMeta.TrivySrv, nil
	}

	s := &TrivySrv{
		PvcPath:       global.ScannerOpts.PvcPath,
		MatcherChan:   make(chan *vulnmatch.Matcher),
		TaskWG:        &sync.WaitGroup{},
		TimeoutSec:    consts.DefaultScanTimeout * 60,
		ImageCacheURL: "0.0.0.0:5566/",
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("VulnSrv"),
			scannerUtils.WithModule(consts.ModuleImageScan),
		),
	}
	for i := range opts {
		opts[i](s)
	}

	// /root/alldb/vuln/
	vulnPath := filepath.Join(s.PvcPath, "vuln")
	updatePath := filepath.Join(vulnPath, "update")

	if err := util.MkdirIfNotExist(vulnPath, false); err != nil {
		return nil, fmt.Errorf("can not create path:%s", vulnPath)
	}

	if err := util.MkdirIfNotExist(updatePath, false); err != nil {
		return nil, fmt.Errorf("can not create path:%s", vulnPath)
	}

	s.VulnRootPath = vulnPath

	_ = os.Setenv("TRIVY_NON_SSL", consts.TrueString)

	workPath := s.vulnDbPath() // /root/alldb/vuln/db/

	ctx := context.Background()

	// scanner镜像自带漏洞库版本号
	nw := s.getVersionFromFile(ctx, filepath.Join(s.GetInitTrivyPath(), consts.VersionStr))
	// 上一个正在使用的版本号
	ex := s.getVersionFromFile(ctx, filepath.Join(workPath, consts.VersionStr))

	if ex.TrivyVersion.Version == "" || !s.compareVersion(ex, nw) {
		// 用户更新了 db，即使 POD 重启，也不应该用老的db覆盖新的db
		// 但是在发版本时，我们会更新 db,此时就要覆盖,所以最好的办法是比较版本号
		// cp 目录下的所有文件，不复制目录本身
		if err := s.copyInitBoltDB(ctx, s.GetInitTrivyPath()); err != nil {
			return nil, err
		}
	}

	// 当前使用的版本号
	s.WorkingVersion = s.getVersionFromFile(context.Background(), filepath.Join(s.vulnDbPath(), consts.VersionStr))

	_ = trivylog.InitLogger(false, false)
	// 优先使用 redis
	if s.RedisCli != nil {
		trivyScanner, err := trivy.NewScannerWithRedis(*s.RedisCli, s.VulnRootPath, false)
		if err != nil {
			s.Log.Err(err).Msg("can not init trivy")
			return nil, err
		}
		s.TrivyScanner = trivyScanner
	}
	if s.CachePath != "" {
		// 实例化好扫描器(不打开漏洞库，只扫描 PKG)
		trivyScanner, err := trivy.NewScannerWithFile(s.CachePath, s.VulnRootPath, false)
		if err != nil {
			s.Log.Err(err).Msg("can not init trivy")
			return nil, err
		}
		s.TrivyScanner = trivyScanner
	}

	s.genVulnMatcherChan(context.Background())

	singleMeta.TrivySrv = s
	s.Log.Info().Interface("WorkingVersion", s.WorkingVersion).Msg("get vuln db version")
	return singleMeta.TrivySrv, nil
}

func (s *TrivySrv) changCacheUrl(im string) (string, error) {
	im = strings.ReplaceAll(im, "https://", "")
	im = strings.ReplaceAll(im, "http://", "")

	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)
	ref, err := name.ParseReference(im, nameOpts...)
	if err != nil {
		s.Log.Err(err).Msg("parse image failed")
		return "", err
	}

	tag := ref.Identifier()
	repositoryName := ref.Context().RepositoryStr()
	newImage := s.ImageCacheURL + repositoryName + ":" + tag
	return newImage, nil
}
