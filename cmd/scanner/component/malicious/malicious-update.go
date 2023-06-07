package malicious

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

type UpdateData struct {
	Path    string
	Version string
}

type UpdataService struct {
	DbPath  string
	Version string
	PvcPath string
	PathCh  chan scannermodel.UpdateResult
}

func NewUpdataService(path string) UpdataService {
	return UpdataService{
		DbPath:  path,
		PvcPath: path,
		PathCh:  make(chan scannermodel.UpdateResult),
	}
}

func (u *UpdataService) GenerateDir(DBpath string) (string, error) {
	tmpDir, err := ioutil.TempDir("/root/", "")
	if err != nil {
		return "", err
	}
	dstPath := filepath.Join(tmpDir, "clamav/")
	osCMD := exec.Command("cp", "-rf", DBpath, dstPath)
	err = osCMD.Run()
	if err != nil {
		os.Remove(tmpDir)
		logging.GetLogger().Err(err).Msgf("%s CP  err :%v", u.DbPath, err)
		return "", err
	}
	return dstPath, nil
}

func (u *UpdataService) UpdateDB(path string) error {
	dbPath := filepath.Join(path, scannermodel.ClamavDBPath)
	osCMD := exec.Command("cp", "-rf", dbPath, filepath.Join(u.PvcPath, scannermodel.MaliciousDir))
	err := osCMD.Run()
	fmt.Println(osCMD.Args)
	if err != nil {
		return err
	}
	return nil
}

func (u *UpdataService) UpdataVersion(ver scannermodel.MaliciousDBVersion) error {
	verByte, err := json.Marshal(ver)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("marshal version struct failed")
		return err
	}
	ioutil.WriteFile(filepath.Join(u.PvcPath, "version"), verByte, 0644)
	return nil
}
