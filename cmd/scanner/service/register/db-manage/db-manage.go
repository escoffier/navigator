package dbManage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"gitlab.com/security-rd/go-pkg/mq"

	vulnupdata "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

const (
	serviceName = "version"
)

type Config struct {
}

type VersionSrv struct {
	PvcPath string
}

func (v *VersionSrv) getVersion(clusterKey string, objType string) (scannermodel.ScanDBVersion, error) {
	nowVulnVer := scannermodel.VulnDBVersion{}
	vulnVer, err := os.ReadFile(filepath.Join(v.PvcPath, scannermodel.VulnVersionPath))
	if err != nil {
		logging.GetLogger().Err(err).Msg("read ver error")
		return scannermodel.ScanDBVersion{}, err
	} else {
		err = json.Unmarshal(vulnVer, &nowVulnVer)
		if err != nil {
			logging.GetLogger().Err(err).Msg("marshal ver error")
			// return scannermodel.ScanDBVersion{}, err
		}
	}

	nowMaliciousVer := scannermodel.MaliciousDBVersion{}
	clamavVer, err := os.ReadFile(filepath.Join(v.PvcPath, scannermodel.ClamavVersionPath))
	if err != nil {
		logging.GetLogger().Err(err).Msg("read ClamavUpdate ver error")
		// return scannermodel.ScanDBVersion{}, err
	} else {
		err = json.Unmarshal(clamavVer, &nowMaliciousVer.Clamav)
		if err != nil {
			logging.GetLogger().Err(err).Msg("marshal ver error")
			return scannermodel.ScanDBVersion{}, err
		}
	}

	aviraVer, err := os.ReadFile(filepath.Join(v.PvcPath, scannermodel.AviraVersionPath))
	if err != nil {
		logging.GetLogger().Err(err).Msg("read avira ver error")
		// return scannermodel.ScanDBVersion{}, err
	} else {
		err = json.Unmarshal(aviraVer, &nowMaliciousVer.Avira)
		if err != nil {
			logging.GetLogger().Err(err).Msg("marshal ver error")
			return scannermodel.ScanDBVersion{}, err
		}
	}

	initDbVersion := scannermodel.ScanDBVersion{
		KeyPath:         clusterKey,
		ObjectType:      scannermodel.MainScannerObject,
		VulnDBVersion:   nowVulnVer,
		ClamavDBVersion: nowMaliciousVer.Clamav,
		AviraDBVersion:  nowMaliciousVer.Avira,
	}
	return initDbVersion, nil
}

func (v *VersionSrv) notMainCluster(ctx context.Context, c *vulnupdata.UpdateVersionSrv) error {
	wr, err := mq.GetClientFactory().Writer(ctx)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get mq writer error")
		return err
	}
	c.MqWriter = wr
	allVer, err := v.getVersion(util.ScannerClusterManagerGrpcStreamKey(global.ClusterKey), scannermodel.SubScannerObject)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get version error")
		return err
	}
	global.VulnDBVersion = &scannermodel.ScannerDBVersion{}
	global.VulnDBVersion.VulnVersion = allVer.VulnDBVersion
	global.VulnDBVersion.MaliciousVersion.Avira = allVer.AviraDBVersion
	global.VulnDBVersion.MaliciousVersion.Clamav = allVer.ClamavDBVersion
	initDbVersion := scannermodel.ScanDBVersion{
		KeyPath:         util.ScannerClusterManagerGrpcStreamKey(global.ClusterKey),
		ObjectType:      scannermodel.SubScannerObject,
		VulnDBVersion:   allVer.VulnDBVersion,
		ClamavDBVersion: allVer.ClamavDBVersion,
		AviraDBVersion:  allVer.AviraDBVersion,
	}
	initByte, err := json.Marshal(initDbVersion)
	if err != nil {
		logging.GetLogger().Err(err).Msg("marshal initDbVersion error")
		return err
	}
	sql := scannermodel.SubScannerToMainSql{DalName: "version", Data: initByte, Action: "create"}
	err = scannermodel.SubScannerSendToKafka(c.MqWriter, sql)
	if err != nil {
		logging.GetLogger().Err(err).Msg("send sql to kafka error")
		return err
	}
	return nil
}

func (v *VersionSrv) isMainCluster(ctx context.Context) error {
	allVer, err := v.getVersion("main", scannermodel.MainScannerObject)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get version error")
		return err
	}
	global.VulnDBVersion = &scannermodel.ScannerDBVersion{}
	global.VulnDBVersion.VulnVersion = allVer.VulnDBVersion
	global.VulnDBVersion.MaliciousVersion.Avira = allVer.AviraDBVersion
	global.VulnDBVersion.MaliciousVersion.Clamav = allVer.ClamavDBVersion
	initDbVersion := scannermodel.ScanDBVersion{
		KeyPath:         scannermodel.MainScannerObject,
		ObjectType:      scannermodel.MainScannerObject,
		VulnDBVersion:   allVer.VulnDBVersion,
		ClamavDBVersion: allVer.ClamavDBVersion,
		AviraDBVersion:  allVer.AviraDBVersion,
	}
	dal := store.GetSingeVersionDao()
	err = dal.UpdateVersion(ctx, initDbVersion, "")
	if err != nil {
		logging.GetLogger().Err(err).Msg("write to db error")
		return err
	}
	trivyMata := scannermodel.ScanDbMateData{DBMata: allVer.VulnDBVersion.TrivyVersion, DBType: scannermodel.TrivyDB}
	customMata := scannermodel.ScanDbMateData{DBMata: allVer.VulnDBVersion.CustomDBVersion, DBType: scannermodel.CustomDB}
	clamavMata := scannermodel.ScanDbMateData{DBMata: allVer.ClamavDBVersion.ClamavVersion, DBType: scannermodel.ClamavDB}
	aviraMata := scannermodel.ScanDbMateData{DBMata: allVer.AviraDBVersion.AvriaVersion, DBType: scannermodel.AviraDB}
	matas := []scannermodel.ScanDbMateData{trivyMata, customMata, clamavMata, aviraMata}
	err = dal.CreateVersionMate(ctx, matas)
	if err != nil {
		logging.GetLogger().Err(err).Msg("write to db error")
		return err
	}
	return nil
}

func (v *VersionSrv) Start(ctx context.Context) error {
	c := vulnupdata.GetUpdateVersionSrv()
	c.PvcPath = v.PvcPath
	isHostCluster := os.Getenv("IS_MAIN_CLUSTER")
	if isHostCluster != "true" {
		err := v.notMainCluster(ctx, c)
		if err != nil {
			logging.GetLogger().Err(err).Msg("init subscanner db version error")
			return err
		}
	} else {
		err := v.isMainCluster(ctx)
		if err != nil {
			logging.GetLogger().Err(err).Msg("init main scanner db version error")
			return err
		}
	}

	return nil
}

func (v *VersionSrv) Stop(ctx context.Context) error {

	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	c := &VersionSrv{PvcPath: config.Options.PvcPath}

	return c, nil
}
