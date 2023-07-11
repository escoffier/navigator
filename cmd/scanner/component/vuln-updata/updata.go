package vulnupdata

// 讲各个模块的更新逻辑在这里整合，也方便上锁和记录

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/avira"
	scanvuln "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/bolt-vuln"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/malicious"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type UpdateVersionSrv struct {
	VulnLock      sync.Mutex
	MaliciousLock sync.Mutex
	InUpdate      map[string]bool
	PvcPath       string
	MqWriter      mq.Writer
}

var (
	srvOnce         sync.Once
	singleUpdateSrv *UpdateVersionSrv
)

func GetUpdateVersionSrv() *UpdateVersionSrv {
	srvOnce.Do(func() {
		singleUpdateSrv = &UpdateVersionSrv{}
		singleUpdateSrv.InUpdate = make(map[string]bool)
	})
	return singleUpdateSrv
}

func (u *UpdateVersionSrv) UpdateVulnDB() (bool, error) {
	scannerVulnUpdata := GetVulnUpdataService()
	filePath, err := scannerVulnUpdata.GenerateDir(filepath.Join(u.PvcPath, "offline", scannermodel.VulnDir))
	if err != nil {
		logging.GetLogger().Err(err).Msgf("gennerate Dir err:%v", err)
		return false, fmt.Errorf("gennerate Dir err:%v", err)
	}
	res := scannermodel.UpdateResult{DBPath: filePath, Result: make(chan bool)}
	scannerVulnUpdata.Ch <- res
	ok := <-res.Result
	if !ok {
		return false, fmt.Errorf("set vuln vuln DB error")
	}
	err = scannerVulnUpdata.UpdateDB(filepath.Join(u.PvcPath, "offline", scannermodel.VulnDir))
	if err != nil {
		logging.GetLogger().Err(err).Msgf("copy new DB failed But new DB is Run (will not update version)")
		return false, fmt.Errorf("copy new DB failed But new DB is Run (will not update version)")
	}
	return true, nil
}

func (u *UpdateVersionSrv) UpdateAvriaDB() (bool, error) {
	aviraSrv := avira.GetaviraSrv()
	err := aviraSrv.UpdateDB(filepath.Join(u.PvcPath, scannermodel.UnzipPath, scannermodel.AviraDBPath))
	if err != nil {
		logging.GetLogger().Err(err).Msgf("avira update error")
		return false, err
	}
	dbPath := filepath.Join(u.PvcPath, scannermodel.UnzipPath, scannermodel.AviraDBPath)
	osCMD := exec.Command("cp", "-rf", dbPath, filepath.Join(u.PvcPath, scannermodel.MaliciousDir))
	err = osCMD.Run()
	fmt.Println(osCMD.Args)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (u *UpdateVersionSrv) UpdateClamAvDB() (bool, error) {
	maliciousSrv := malicious.GetMaliciousServer()
	dst, err := maliciousSrv.Updata.GenerateDir(filepath.Join(maliciousSrv.Updata.PvcPath, scannermodel.UnzipPath, scannermodel.ClamavDBPath))
	if err != nil {
		logging.GetLogger().Err(err).Msgf("generateDir err :%v", err)
		return false, fmt.Errorf("generateDir err :%v", err)
	}
	res := scannermodel.UpdateResult{DBPath: dst, Result: make(chan bool)}
	maliciousSrv.Updata.PathCh <- res
	ok := <-res.Result
	if !ok {
		return false, fmt.Errorf("load clamDB error")
	}
	maliciousSrv.Updata.UpdateDB(filepath.Join(maliciousSrv.Updata.PvcPath, scannermodel.UnzipPath))
	return true, nil
}

// 与前两种的更新方式略有差别，临时方案。等中文库整合进trivyDB后该流程会废除
func (u *UpdateVersionSrv) UpdateBoltDB() (bool, error) {
	vuln := scanvuln.GetSingleBoltVuln()
	err := vuln.InitDB(filepath.Join(u.PvcPath, scannermodel.UnzipPath, scannermodel.VulnDir))
	if err != nil {
		logging.GetLogger().Err(err).Msgf("init db err :%v", err)
		return false, fmt.Errorf("init db err :%v", err)
	}
	err = vuln.UpdateDB(filepath.Join(u.PvcPath, scannermodel.UnzipPath, scannermodel.VulnDir))
	if err != nil {
		return false, fmt.Errorf("updateDB error but new DB is load")
	}
	return true, nil
}

func (u *UpdateVersionSrv) UpdateMaliciousVersion(ver scannermodel.MaliciousDBVersion, objType string) error {
	if objType == scannermodel.ClamavDB {
		verByte, err := json.Marshal(ver.Clamav)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("marshal version struct failed")
			return err
		}
		ioutil.WriteFile(filepath.Join(u.PvcPath, scannermodel.ClamavVersionPath), verByte, 0644)
	} else if objType == scannermodel.AviraDB {
		verByte, err := json.Marshal(ver.Avira)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("marshal version struct failed")
			return err
		}
		ioutil.WriteFile(filepath.Join(u.PvcPath, scannermodel.AviraVersionPath), verByte, 0644)
	}
	return nil
}

func (u *UpdateVersionSrv) UpdateVulnVersion(ver scannermodel.VulnDBVersion) error {
	verByte, err := json.Marshal(ver)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("marshal version struct failed")
		return err
	}
	ioutil.WriteFile(filepath.Join(u.PvcPath, scannermodel.VulnVersionPath), verByte, 0644)
	return nil
}

func (u *UpdateVersionSrv) CheckVulnHash(ver scannermodel.VulnDBVersion, path string) bool {
	trivyHash, err := util.Md5FromFile(filepath.Join(path, scannermodel.TrivyDBPath))
	if err != nil {
		logging.GetLogger().Err(err).Msg("get trivyDB hash fasle")
		return false
	}
	customHash, err := util.Md5FromFile(filepath.Join(path, scannermodel.CustomDBPath))
	if err != nil {
		logging.GetLogger().Err(err).Msg("get custom hash fasle")
		return false
	}
	if ver.TrivyVersion.Hash == trivyHash && ver.CustomDBVersion.Hash == customHash {
		return true
	} else {
		logging.GetLogger().Err(err).Msgf("hash not match vertrivy:%v nowtrivy:%v vercustom:%v nowcustom:%v", ver.TrivyVersion.Hash, trivyHash, ver.CustomDBVersion.Hash, customHash)
		return false
	}
}

func (u *UpdateVersionSrv) CheckMaliciousHash(ctx context.Context, ver scannermodel.MaliciousDBVersion, path string) bool {
	clamavMainHash, err := util.Md5FromFile(filepath.Join(path, scannermodel.ClamavDBPath, "main.cvd"))
	if err != nil {
		logging.GetLogger().Err(err).Msg("get clamav hash fasle")
		return false
	}
	clamavDailyHash, err := util.Md5FromFile(filepath.Join(path, scannermodel.ClamavDBPath, "daily.cld"))
	if err != nil {
		logging.GetLogger().Err(err).Msg("get clamav hash fasle")
		return false
	}
	clamavHash := clamavMainHash + clamavDailyHash
	if ver.Clamav.ClamavVersion.Hash == clamavHash {
		return true
	}
	return false
}

func SaveFile(data []byte, path string) error {
	fs, err := os.Create(path)
	if err != nil {
		return err
	}
	defer fs.Close()
	red := bytes.NewReader(data)
	_, err = io.Copy(fs, red)
	if err != nil {
		return err
	}
	return nil
}
