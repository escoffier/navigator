package scanner_vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/avast/retry-go"
	"github.com/boltdb/bolt"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnnvd"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnvd"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScannerVuln struct {
	lock     *sync.RWMutex
	customDB *bolt.DB
	dbPath   string
	PvcPath  string
}

type VulnDetail struct {
	Cnvd  []cnvd.CnvdMetadata
	Cnnvd cnnvd.CNNVDVulnerabilityInfo
}

var (
	once        sync.Once
	scannerVuln *ScannerVuln
)

func GetScannerVuln() *ScannerVuln {
	return scannerVuln
}
func CheckList(pvcPath string) bool {
	fileList := []string{"init_trivy.db", "init_custom.db", "custom_init_version", "trivy_init_version"}
	for k := range fileList {
		if !util.FileExists(filepath.Join(pvcPath, fileList[k])) {
			logging.GetLogger().Info().Msgf("File %v not exist while sleep 10S", filepath.Join(pvcPath, fileList[k]))
			return false
		}
	}
	return true
}
func NewScannerVuln(pvcPath string) *ScannerVuln {
	for {
		if CheckList(pvcPath) {
			break
		} else {
			time.Sleep(time.Second * 10)
		}
	}
	once.Do(func() {
		scannerVuln = &ScannerVuln{}
		scannerVuln.PvcPath = pvcPath
		scannerVuln.lock = new(sync.RWMutex)
	})
	return scannerVuln
}

func (s *ScannerVuln) GetDBPath() (string, error) {
	tmpDir, err := ioutil.TempDir(s.PvcPath, "")
	if err != nil {
		return "", err
	}
	fp := filepath.Join(tmpDir, "custom.db")
	lastDbPath := filepath.Join(s.PvcPath, "last_custom.db")
	osCMD := exec.Command("cp", "-f", lastDbPath, fp)
	err = osCMD.Run()
	if err != nil {
		logging.GetLogger().Error().Msgf("failed to cp %v", err)
		return "", err
	}
	return tmpDir, nil
}

func (s *ScannerVuln) TickerRun() error {
	preDir := s.dbPath
	err := s.InitDB()
	if err != nil {
		if s.customDB == nil {
			var options bolt.Options
			options.Timeout = time.Second * 15
			dbFp := filepath.Join(preDir, "custom.db")
			var terr error
			s.customDB, terr = bolt.Open(dbFp, 0600, &options)
			if terr != nil {
				logging.GetLogger().Error().Err(terr).Msg("TickerRun error And Init Db error:")
			}
		}
		logging.GetLogger().Error().Err(err).Msg("TickerRun error")
	}
	return nil
}

func CompareVersion(vtype string, old string, new string) bool {
	if len(new) < 4 {
		return true
	}
	if strings.Contains(vtype, "trivy") {
		old = old[3:]
		new = new[3:]
		logging.GetLogger().Info().Msgf("CompareVersion old :%v new:%v", old, new)
		oldNum, _ := strconv.Atoi(old)
		newNum, _ := strconv.Atoi(new)
		return oldNum > newNum
	} else if strings.Contains(vtype, "custom") {

		timeLayout := "2006-01-02 15:04:05"
		oldTime, _ := time.ParseInLocation(timeLayout, strings.TrimRight(old, "\n"), time.Local)
		newTime, _ := time.ParseInLocation(timeLayout, strings.TrimRight(new, "\n"), time.Local)
		oldTimeUnix := oldTime.Unix()
		newTimeUnix := newTime.Unix()
		logging.GetLogger().Info().Msgf("CompareVersion old :%v new:%v", oldTimeUnix, newTimeUnix)
		return oldTimeUnix > newTimeUnix
	}
	return true
}

func (s *ScannerVuln) ReadVersion(name string) string {
	res := "last"
	if strings.Contains(name, "custom") {
		offlineVersion := "2006-01-02 15:04:04"
		CustomVersion := ""
		if util.FileExists(filepath.Join(s.PvcPath, "custom_version")) {
			CustomVersionBytes, err := os.ReadFile(filepath.Join(s.PvcPath, "custom_version"))
			if err != nil {
				logging.GetLogger().Error().Err(err).Msgf("Open now Custom version Error")
				CustomVersion = "2006-01-02 15:04:05"
			} else {
				CustomVersion = string(CustomVersionBytes)
				res = "last"
			}
		}
		if util.FileExists(filepath.Join(s.PvcPath, "offline", "custom_init_version")) {
			CustomVersionBytes, err := os.ReadFile(filepath.Join(s.PvcPath, "offline", "custom_init_version"))
			if err != nil {
				logging.GetLogger().Error().Err(err).Msgf("Open Offline Custom version Error")
			} else {
				offlineVersion = string(CustomVersionBytes)
			}
		}
		if !CompareVersion("custom", CustomVersion, offlineVersion) {
			res = "offline"
		}
	}
	return res
}
func (s *ScannerVuln) getVulnPath() string {
	version := s.ReadVersion("custom")
	if version == "last" {
		return filepath.Join(s.PvcPath, "last_custom.db")
	} else {
		return filepath.Join(s.PvcPath, "offline", "init_custom.db")
	}
}

func (s *ScannerVuln) InitDB() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	tmpDir, err := ioutil.TempDir("/root/", "")
	if err != nil {
		return err
	}
	fp := filepath.Join(tmpDir, "custom.db")
	lastDbPath := s.getVulnPath()
	osCMD := exec.Command("cp", "-f", lastDbPath, fp)
	err = osCMD.Run()
	fmt.Println(lastDbPath)
	fmt.Println(osCMD.Args)
	if err != nil {
		os.RemoveAll(tmpDir)
		logging.GetLogger().Error().Msgf("failed to cp %v", err)
		return err
	}
	if s.customDB != nil {
		s.customDB.Close()
		s.customDB = nil
	}
	var options bolt.Options
	options.Timeout = time.Second * 15
	db1, err := bolt.Open(fp, 0600, &options)
	if err != nil {
		os.RemoveAll(tmpDir)
		if s.dbPath != "" {
			var terr error
			s.customDB, terr = bolt.Open(filepath.Join(s.dbPath, "custom.db"), 0600, &options)
			if terr != nil {
				logging.GetLogger().Error().Err(terr).Msgf("update CustomDb failed and open old Db failed too")
			}
		}
		return fmt.Errorf("Init Bolt err %v", err)
	}
	os.RemoveAll(s.dbPath)
	s.dbPath = tmpDir
	s.customDB = db1
	return nil
}

func (s *ScannerVuln) Run() {
	defer func() {
		if s.dbPath != "" {
			os.RemoveAll(s.dbPath)
		}
	}()
	retryOptions := []retry.Option{
		retry.DelayType(retry.FixedDelay),
		retry.Attempts(10),
		retry.Delay(time.Duration(10) * time.Second),
	}
	ctx := context.Background()
	err := util.RetryWithBackoff(ctx, func() error {
		err := s.InitDB()
		if err != nil {
			logging.GetLogger().Error().Msgf("Init Db failed,try restart %v", err)
		}
		return err
	}, retryOptions...)

	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("scan vuln run err ")
		return
	}

	ticker := time.NewTicker(time.Hour * 6)
	defer ticker.Stop()
	for range ticker.C {
		err := s.TickerRun()
		if err != nil {
			logging.GetLogger().Error().Msgf("failed to TickerRun %v", err)
		}
	}
}

func (s *ScannerVuln) GetVulnDetail(name string) (VulnDetail, error) {
	logging.GetLogger().Info().Msgf("IN Query %s", name)
	if s.customDB == nil {
		return VulnDetail{}, fmt.Errorf("db not open")
	}
	s.lock.RLock()
	defer s.lock.RUnlock()
	res := VulnDetail{}
	if s.customDB != nil {
		_ = s.customDB.View(func(tx *bolt.Tx) error { //customDB
			var err error
			cnvdBucket := tx.Bucket([]byte("cnvd"))
			if cnvdBucket == nil {
				logging.GetLogger().Error().Msg("get cnvdBucket err")
				return fmt.Errorf("get cnvdBucket err")
			}
			cnvdResByte := cnvdBucket.Get([]byte(name))
			cnvdRes := []cnvd.CnvdMetadata{}
			if cnvdResByte != nil {
				err = json.Unmarshal(cnvdResByte, &cnvdRes)
				if err != nil {
					logging.GetLogger().Error().Msgf("unmarshal cnvdRes err :%v", err)
					return err
				}
			}
			res.Cnvd = cnvdRes
			cnnvdBucket := tx.Bucket([]byte("cnnvd"))
			if cnnvdBucket == nil {
				logging.GetLogger().Error().Msgf("get cnnvdBucker err")
				return fmt.Errorf("get cnnvdBucker err")
			}
			cnnvdResByte := cnnvdBucket.Get([]byte(name))
			cnnvdRes := cnnvd.CNNVDVulnerabilityInfo{}
			if cnnvdResByte != nil {
				err = json.Unmarshal(cnnvdResByte, &cnnvdRes)
				if err != nil {
					logging.GetLogger().Error().Msgf("unmarshal cnnvdRes err :%v", err)
					return err
				}

			}
			res.Cnnvd = cnnvdRes
			return nil
		})
	}
	return res, nil
}
