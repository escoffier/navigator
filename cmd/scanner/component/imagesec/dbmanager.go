package imagesec

import (
	"context"
	"encoding/json"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/global"
	imagescanSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type DBUpdateService interface {
	UpdateVulnDb(ctx context.Context, param imagesecModel.UpdateDbParam) error
	SearchScanDb(ctx context.Context, param imagesecModel.SearchScanDbParam) ([]*imagesecModel.ScanConfigDB, int64, error)
}

type Updater interface {
	UpdateDB(ctx context.Context, param imagesecModel.UpdateDbParam) (*imagesecModel.ScanConfigDB, error)
	GetWorkVersion(ctx context.Context) (*imagesecModel.ScanConfigDB, error)
}

type DBUpdateSrv struct {
	VulnUpdate    Updater
	ScanDbMetaDal imagesecStore.ScanDbMetaDal
	ScanConfigDal imagesecStore.ScanImageConfigDal
	Log           *scannerUtils.LogEvent
	WorkVersion   string
}

func NewDBUpdateSrv(
	vulnUpdate Updater,
	scanDbMetaDal imagesecStore.ScanDbMetaDal,
	scanConfigDal imagesecStore.ScanImageConfigDal,
) *DBUpdateSrv {
	s := &DBUpdateSrv{VulnUpdate: vulnUpdate,
		ScanDbMetaDal: scanDbMetaDal,
		ScanConfigDal: scanConfigDal,
		Log:           scannerUtils.NewLogEvent(scannerUtils.WithModule(consts.ModuleUBUpdate)),
	}
	_ = s.CreateWorkingVulnVer(context.Background())
	_ = s.StartBackgroundUpdater(context.Background())
	return s
}

func (s *DBUpdateSrv) UpdateVulnDb(ctx context.Context, param imagesecModel.UpdateDbParam) error {
	global.VulnVer = ""

	db, err := s.VulnUpdate.UpdateDB(ctx, param)
	if err != nil {
		s.Log.Err(err).Msg("update vuln db")
		return err
	}
	// 入库
	if err := s.ScanDbMetaDal.CreateScanDbMeta(ctx, db); err != nil {
		s.Log.Err(err).Interface("param", param).Msg("CreateScanDbMeta vuln db")
		return err
	}
	// 增加扫描任务
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Msg("CreateSensitiveRule create scan task")
			}
		}()
		scan := imagescanSrv.MustGetScanTaskSrv()
		if err := scan.TrigCreateScanTask(ctx, imagesecModel.VulnDbUpdateTrigger); err != nil {
			s.Log.Err(err).Str("configType", imagesecModel.VulnDbUpdateTrigger).Msg("UpdateVulnDb CreateImageScanTask")
		}
		s.Log.Info().Msg("TrigCreateScanTask")
	}()
	return nil
}

func (s *DBUpdateSrv) SearchScanDb(ctx context.Context, param imagesecModel.SearchScanDbParam) ([]*imagesecModel.ScanConfigDB, int64, error) {
	his, i, err := s.ScanDbMetaDal.SearchScanDbMeta(ctx, param)
	if err != nil {
		s.Log.Err(err).Interface("param", param).Msg("SearchScanDb vuln db")
		return his, i, err
	}

	return his, i, err
}

func (s *DBUpdateSrv) StartBackgroundUpdater(ctx context.Context) error {
	if !scannerUtils.MainCluster() {
		s.Log.Info().Msg("not in main cluster, skip DB updater")
		return nil
	}
	// start background updater
	if global.ScannerOpts == nil || global.ScannerOpts.HuaweiSecretId == "" || global.ScannerOpts.HuaweiSecretKey == "" ||
		global.ScannerOpts.HuaweiVulnBucket == "" {
		s.Log.Info().Msg("huawei vuln bucket not set, skip DB updater")
		return nil
	}

	obsCli, err := NewObsApi(
		WithSecret(global.ScannerOpts.HuaweiSecretId, global.ScannerOpts.HuaweiSecretKey),
		WithEndpoint(global.ScannerOpts.HuaweiEndpoint),
		WithBucket(global.ScannerOpts.HuaweiVulnBucket),
	)
	if err != nil {
		logging.GetLogger().Err(err).Msg("init obs client failed")
		return err
	}

	s.Log.Info().Str("obsbucket", obsCli.bucket).Str("endpoint", obsCli.endpoint).Msg("obs config")

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Msgf("panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		mi := os.Getenv("VULN_ONLINE_PER_MIMI")
		mii, err := strconv.Atoi(mi)
		if err != nil || mii <= 0 {
			mii = 5
		}
		ticker := time.NewTicker(time.Minute * time.Duration(int64(mii)))
		defer ticker.Stop()
		for {
			<-ticker.C
			// 查询当前策略，是否开启动自动更新
			cfg, err := s.ScanConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeVulnDBUpdate)
			if err != nil {
				s.Log.Err(err).Msg("GetScanImageConfig")
				continue
			}
			if cfg.VulnDBUpdate == nil || cfg.VulnDBUpdate.EnableOnline == consts.FalseString {
				s.Log.Info().Msg("vuln db update is not enabled")
				continue
			}

			// 1) get remote version json from OBS
			s.Log.Info().Msg("GetLastUpdateKey")
			verKey, zipKey, err := s.GetLastUpdateKey(ctx)
			if err != nil {
				s.Log.Err(err).Msg("GetLastUpdateKey")
				continue
			}
			verBytes, err := obsCli.GetObjectContent(ctx, verKey)
			if err != nil {
				s.Log.Err(err).Str("key", verKey).Msg("GetObjectContent version")
				continue
			}

			var ver struct {
				TrivyVersion struct {
					Version string `json:"version"`
					Comment string `json:"comment"`
					Hash    string `json:"hash"`
				} `json:"trivyVersion"`
			}
			if err := json.Unmarshal(verBytes, &ver); err != nil {
				s.Log.Err(err).Str("key", verKey).Msg("Unmarshal version json")
				continue
			}
			remoteCompress := ver.TrivyVersion.Version
			if s.WorkVersion != "" && s.WorkVersion >= remoteCompress {
				s.Log.Info().Str("remoteCompress", remoteCompress).Str("localCompress", s.WorkVersion).Msg("vuln db do not need update")
				continue
			}
			s.Log.Info().Str("remoteCompress", remoteCompress).Str("localCompress", s.WorkVersion).Msg("need update vuln db")
			// 2) fetch vuln zip
			zipBytes, err := obsCli.GetObjectContent(ctx, zipKey)
			if err != nil {
				s.Log.Err(err).Str("key", zipKey).Msg("GetObjectContent vuln.zip")
				continue
			}
			// 3) update db
			param := imagesecModel.UpdateDbParam{Updater: consts.UpdaterCycle, DbType: consts.TrivyName, Data: zipBytes, CheckVersion: false}
			if err := s.UpdateVulnDb(ctx, param); err != nil {
				s.Log.Err(err).Msg("UpdateVulnDb")
				continue
			}
			s.WorkVersion = remoteCompress
			s.Log.Info().Str("TrivyDbVersion", s.WorkVersion).Msg("update vuln db success")
		}
	}()
	return nil
}

func (s *DBUpdateSrv) CreateWorkingVulnVer(ctx context.Context) error {
	ver, err := s.VulnUpdate.GetWorkVersion(ctx)
	if err != nil {
		s.Log.Err(err).Msg("get vuln working version")
		return err
	}
	s.WorkVersion = ver.DBVersion

	pre, _, err := s.SearchScanDb(ctx, imagesecModel.SearchScanDbParam{
		DBType:    consts.TrivyName,
		DBVersion: ver.DBVersion,
	})
	if err != nil {
		s.Log.Err(err).Str("version", ver.DBVersion).Msg("CreateWorkingVulnVer")
		return err
	}
	if len(pre) > 0 {
		return nil
	}
	ver.DBType = consts.TrivyName
	ver.Updater = consts.DefaultAdminUser

	if err := s.ScanDbMetaDal.CreateScanDbMeta(ctx, ver); err != nil {
		s.Log.Err(err).Str("version", ver.DBVersion).Msg("CreateScanDbMeta")
		return err
	}
	return nil
}

func (s *DBUpdateSrv) GetLastUpdateKey(ctx context.Context) (string, string, error) {
	versions := make([]string, 0)
	zipKeys := make([]string, 0)

	obsCli, err := NewObsApi(
		WithSecret(global.ScannerOpts.HuaweiSecretId, global.ScannerOpts.HuaweiSecretKey),
		WithEndpoint(global.ScannerOpts.HuaweiEndpoint),
		WithBucket(global.ScannerOpts.HuaweiVulnBucket),
	)
	if err != nil {
		s.Log.Err(err).Msg("NewObsApi")
		return "", "", err
	}
	dirs, err := obsCli.GetAllObj(ctx)
	if err != nil {
		s.Log.Err(err).Msg("GetAllObj")
		return "", "", err
	}
	zipKey := global.ScannerOpts.VulnZipKey
	verKey := global.ScannerOpts.VulnVersionKey

	for _, dir := range dirs {
		if strings.Contains(dir, "/") && strings.Contains(dir, verKey) {
			versions = append(versions, dir)
		}
		if strings.Contains(dir, "/") && strings.Contains(dir, zipKey) {
			zipKeys = append(zipKeys, dir)
		}
	}
	if len(versions) == 0 || len(zipKeys) == 0 {
		s.Log.Info().Msg("no vuln db in obs")
		return "", "", nil
	}
	sort.Strings(versions)
	sort.Strings(zipKeys)
	s.Log.Info().Str("versions", strings.Join(versions, ",")).Str("zipKeys", strings.Join(zipKeys, ",")).Msg("GetLastUpdateKey")
	ver := versions[len(versions)-1]
	zip := zipKeys[len(zipKeys)-1]
	verPrefix := strings.Split(ver, "/")
	zipPrefix := strings.Split(zip, "/")

	if len(verPrefix) == 0 || len(verPrefix) != len(zipPrefix) || verPrefix[0] != zipPrefix[0] {
		s.Log.Info().Str("ver", ver).Str("zip", zip).Msg("GetLastUpdateKey")
		return "", "", nil
	}

	s.Log.Info().Str("verKey", ver).Str("zipKey", zip).Msg("GetLastUpdateKey")
	return ver, zip, nil
}
