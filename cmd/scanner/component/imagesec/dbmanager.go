package imagesec

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/global"
	imagescanSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
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
	Log           *scannerUtils.LogEvent
}

func NewDBUpdateSrv(
	vulnUpdate Updater,
	scanDbMetaDal imagesecStore.ScanDbMetaDal,
) *DBUpdateSrv {
	s := &DBUpdateSrv{VulnUpdate: vulnUpdate,
		ScanDbMetaDal: scanDbMetaDal,
		Log:           scannerUtils.NewLogEvent(scannerUtils.WithModule(consts.ModuleUBUpdate)),
	}
	_ = s.CreateWorkingVulnVer(context.Background())
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

// 如果如用户没有更新过漏洞库，那么应该把发版的漏洞库写入版本管理中
func (s *DBUpdateSrv) CreateWorkingVulnVer(ctx context.Context) error {
	ver, err := s.VulnUpdate.GetWorkVersion(ctx)
	if err != nil {
		s.Log.Err(err).Msg("get vuln working version")
		return err
	}
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
