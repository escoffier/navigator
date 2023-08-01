package avira

import (
	"fmt"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-json"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	DefaultDBPath  = "/usr/local/savapi-sdk-linux64/"
	DefaultBinPath = "/usr/local/savapi-sdk-linux64/bin/savapi"
	BinPath        = "bin/savapi"
	confPath       = "/etc/savapi/savapi.conf"
)

var (
	once     sync.Once
	instance *AvriaSrv
)

type AvriaSrv struct {
	UpdateSrv *AviraUpdate
}

type AviraUpdate struct {
	DBPath   string
	Version  string
	IsUpdate atomic.Int32
}

func (au *AviraUpdate) GenerateDir(dbPath string) (string, error) {
	dstDir, err := ioutil.TempDir("/root", "")
	if err != nil {
		logging.GetLogger().Err(err).Msg("create tempDir error")
		return "", err
	}
	cmd := exec.Command("cp", "-r", dbPath, dstDir)
	err = cmd.Run()
	if err != nil {
		logging.GetLogger().Err(err).Msgf("cp avira db error %v", cmd.Args)
		return "", err
	}
	dstDir = filepath.Join(dstDir, scannermodel.AviraDB)
	return dstDir, nil
}

// 默认获取version成功即二进制和病毒库可用
func (au *AviraUpdate) GetVersion(savapiPath string) (string, error) {
	cmd := exec.Command("chmod", "+x", savapiPath)
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	cmd = exec.Command(savapiPath, "--version")
	out, err := cmd.CombinedOutput()
	version := ""
	if err != nil && !strings.Contains(err.Error(), "exit status 101") {
		logging.GetLogger().Err(err).Msgf("get avira version error")
		return version, err
	}
	strOut := string(out)
	strs := strings.Split(strOut, "\n")
	for k := range strs {
		if strings.Contains(strs[k], "Packlib version:") {
			versionLine := strings.Split(strs[k], ":")
			if len(versionLine) < 2 {
				return version, fmt.Errorf("Packlib version not have :")
			}
			version = strings.Trim(versionLine[1], " ")
		}
	}
	if version == "" {
		return version, fmt.Errorf("can't get version may be fault db")
	}
	return version, nil
}

func (au *AviraUpdate) GenerateVersionFile(dirPath string) error {
	verFile := scannermodel.AviraDBVersion{ComPressDBVersion: "auto generate"}
	version, err := au.GetVersion(filepath.Join(dirPath, BinPath))
	if err != nil {
		return err
	}
	au.Version = version
	if util.FileExists(filepath.Join(dirPath, "version")) {
		return nil
	}
	aviraVer := scannermodel.DBMateData{Version: version}
	md5Str, err := util.Md5FromFile(filepath.Join(dirPath, BinPath))
	if err != nil {
		return err
	}
	aviraVer.Hash = md5Str
	verFile.AvriaVersion = aviraVer
	verByte, err := json.Marshal(verFile)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(dirPath, "version"), verByte, 0600)
	if err != nil {
		return err
	}
	return nil
}

func (au *AviraUpdate) transVersion(version string) (int, error) {
	strs := strings.Split(version, ".")
	res := 0
	for k := range strs {
		tmp, err := strconv.Atoi(strs[k])
		if err != nil {
			logging.GetLogger().Err(err).Msgf("transVersion error in %v", version)
			return res, err
		}
		res = res*10 + tmp
	}
	return res, nil
}

func NewaviraSrv(updater *AviraUpdate) *AvriaSrv {
	once.Do(func() {
		avira := AvriaSrv{UpdateSrv: updater}
		instance = &avira
		return
	})
	return instance
}

func GetaviraSrv() *AvriaSrv {
	return instance
}

func (as *AvriaSrv) Stop(IsUpdate int32) error {
	as.UpdateSrv.IsUpdate.Store(IsUpdate)
	cmd := exec.Command(filepath.Join(as.UpdateSrv.DBPath, BinPath), "--stop", "-C", "/etc/savapi/savapi.conf")
	out, err := cmd.CombinedOutput()
	if err != nil {
		logging.GetLogger().Err(err).Msgf("stop avira error %v %v", cmd.Args, string(out))
		return err
	}
	if strings.Contains(string(out), "successful") {
		return nil
	} else {
		return fmt.Errorf("cmd run ok but stop failed %v", out)
	}
}

func (as *AvriaSrv) UpdateDB(dbPath string) error {
	scanLock.Lock()
	defer scanLock.Unlock()
	newPath := filepath.Join(dbPath, BinPath)
	newVer, err := as.UpdateSrv.GetVersion(newPath)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get version from new db dir failed may be file error")
		return err
	}

	dstPath, err := as.UpdateSrv.GenerateDir(dbPath)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("generate avira temp dir error")
		return err
	}
	err = as.Stop(1)
	if err != nil {
		logging.GetLogger().Error().Msgf("avira stop old dir error restart old dir")
		as.UpdateSrv.IsUpdate.Store(0)
	}
	err = as.StartSrv(filepath.Join(dstPath, BinPath))
	if err != nil {
		as.UpdateSrv.IsUpdate.Store(1)
		as.StartSrv(filepath.Join(as.UpdateSrv.DBPath, BinPath))
		time.Sleep(time.Second * 5)
		as.UpdateSrv.IsUpdate.Store(0)
		return err
	}
	as.UpdateSrv.DBPath = dstPath
	as.UpdateSrv.IsUpdate.Store(0)
	as.UpdateSrv.Version = newVer

	return nil
}

func (as *AvriaSrv) StartSrv(dbPath string) error {
	go func() {
		failCount := 0
		for {
			cmd := exec.Command(dbPath, "-N", "-C", "/etc/savapi/savapi.conf")
			err := cmd.Start()
			if err != nil {
				logging.GetLogger().Err(err).Msg("start avira service err")
			}
			logging.GetLogger().Info().Msg("start avira service")
			cmd.Wait()
			if as.UpdateSrv.IsUpdate.Load() == 1 {
				logging.GetLogger().Info().Msg("avira service exit to update")
				return
			}
			failCount++
			if failCount >= 10 {
				break
			}
			logging.GetLogger().Err(err).Msgf("avira service exit, failCount: %d %v", failCount, cmd.Args)
			time.Sleep(5 * time.Second)
		}
	}()
	return nil
}
