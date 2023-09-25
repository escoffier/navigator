package malicious

// import (
// 	"context"
// 	"encoding/json"
// 	"io/ioutil"
// 	"os"
// 	"os/exec"
// 	"path/filepath"
// 	"sync/atomic"
//
// 	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/avira"
// 	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/malicious"
// 	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
// 	"gitlab.com/piccolo_su/vegeta/pkg/logging"
// 	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
// 	"gitlab.com/piccolo_su/vegeta/pkg/util"
// )
//
// const (
// 	serviceName = "malicious-service"
// )
//
// type Config struct {
// }
//
// type MaliceService struct {
// 	maliceService *malicious.MaliciousServer
// 	avriaService  *avira.AvriaSrv
// }
//
// func (m *MaliceService) InitDbPath(vulnPath string) bool {
// 	nowFp := filepath.Join(vulnPath, scannermodel.ClamavDBPath, "daily.cvd")
// 	if util.FileExists(nowFp) {
// 		return true
// 	}
//
// 	cmd := exec.Command("cp", "-rf", "/var/lib/clamav", filepath.Join(vulnPath, scannermodel.MaliciousDir))
// 	err := cmd.Run()
// 	if err != nil {
// 		logging.GetLogger().Err(err).Msgf("cp initDB error %v", cmd.Args)
// 		return false
// 	}
// 	defaultVer := scannermodel.ClamavDBVersion{}
// 	defaultVer.ComPressDBVersion = "default"
// 	defaultVer.ClamavVersion.Version = "000000000000"
// 	defaultVerByte, err := json.Marshal(defaultVer)
// 	if err != nil {
// 		logging.GetLogger().Err(err).Msg("marshal default ver error")
// 		return false
// 	}
//
// 	err = ioutil.WriteFile(filepath.Join(vulnPath, scannermodel.ClamavVersionPath), defaultVerByte, 0600)
// 	if err != nil {
// 		logging.GetLogger().Err(err).Msg("write default ver error")
// 		return false
// 	}
// 	return true
// }
//
// func (m *MaliceService) Start(ctx context.Context) error {
// 	if os.Getenv("SCAN_VIRUS") != scannermodel.EnvAvira {
// 		go m.maliceService.Run()
// 		up := scannermodel.UpdateResult{DBPath: m.maliceService.Updata.DbPath, Result: make(chan bool)}
// 		m.maliceService.Updata.PathCh <- up
// 		res := <-up.Result
// 		if res == false {
// 			logging.GetLogger().Error().Msg("start Malicous egine error")
// 		}
// 	} else {
// 		dstPath, err := m.avriaService.UpdateSrv.GenerateDir(m.avriaService.UpdateSrv.DBPath)
// 		if err != nil {
// 			logging.GetLogger().Err(err).Msgf("generate avira temp dir error")
// 			return err
// 		}
// 		m.avriaService.StartSrv(filepath.Join(dstPath, avira.BinPath))
// 		m.avriaService.UpdateSrv.DBPath = dstPath
// 	}
// 	return nil
// }
//
// func (m *MaliceService) Stop(ctx context.Context) error {
// 	return nil
// }
//
// func init() {
// 	register.Register(serviceName, newService)
// }
//
// func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
// 	m, err := malicious.NewMaliciousServer()
// 	if err != nil {
// 		return nil, err
// 	}
// 	u := malicious.NewUpdateService(config.Options.PvcPath)
// 	m.Updata = u
// 	dbPath := avira.DefaultDBPath
// 	pvcAvriaPath := filepath.Join(config.Options.PvcPath, scannermodel.AviraDBPath)
// 	if util.FileExists(pvcAvriaPath) {
// 		dbPath = pvcAvriaPath
// 	} else {
// 		cmd := exec.Command("cp", "-r", avira.DefaultDBPath, pvcAvriaPath)
// 		err = cmd.Run()
// 		if err != nil {
// 			logging.GetLogger().Warn().Msgf("cp default path error %v but will run", err)
// 		} else {
// 			dbPath = pvcAvriaPath
// 		}
// 	}
// 	up := avira.AviraUpdate{DBPath: dbPath, IsUpdate: atomic.Int32{}}
// 	err = up.GenerateVersionFile(dbPath)
// 	if err != nil {
// 		logging.GetLogger().Warn().Msgf("GenerateVersionFile savapi version error")
// 	}
// 	up.IsUpdate.Store(0)
// 	as := avira.NewaviraSrv(&up)
//
// 	svc := MaliceService{maliceService: m, avriaService: as}
// 	res := svc.InitDbPath(svc.maliceService.Updata.DbPath)
// 	if !res {
// 		svc.maliceService.Updata.DbPath = "/var/lib/clamav"
// 	} else {
// 		svc.maliceService.Updata.DbPath = filepath.Join(svc.maliceService.Updata.PvcPath, scannermodel.ClamavDBPath)
// 	}
// 	return &svc, nil
// }
