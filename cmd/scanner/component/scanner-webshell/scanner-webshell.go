package scanwebshell

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

type ScannerWebshell struct {
	Token int
}

var token chan int
var once sync.Once

func init() {
	numStr := os.Getenv("WebshellNum")
	var num int
	var err error
	if numStr != "" {
		num, err = strconv.Atoi(numStr)
		if err != nil {
			num = 5
			logging.GetLogger().Err(err).Msgf("get websehllNum env error")
		}
	} else {
		num = 5
	}
	CreateToken(num)
}

func CreateToken(n int) {
	once.Do(func() {
		token = make(chan int, n)
		for i := 1; i <= n; i++ {
			token <- i
		}
	})
}

func GetService(ctx context.Context) (*ScannerWebshell, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case n := <-token:
		return &ScannerWebshell{Token: n}, nil
	}
}

func (s *ScannerWebshell) BackServe() { // 理论上只要外部调用代码不写错，这里是不会有阻塞的
	token <- s.Token
}

func (s *ScannerWebshell) PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

func (s *ScannerWebshell) cmdScan(path string, scanPath string) error {
	dbPath := filepath.Join(path, "data.db")
	if s.PathExists(dbPath) {
		err := s.removeDb(dbPath)
		if err != nil {
			logging.GetLogger().Err(err).Msg("remove data db error")
			return err
		}
	}
	binPath := filepath.Join(path, "hm")
	cmd := exec.Command(binPath, "scan", scanPath)
	_, err := cmd.CombinedOutput()
	if err != nil {
		logging.GetLogger().Err(err).Msg("cmd.Run() failed")
		return err
	}
	return nil
}

func (s *ScannerWebshell) parseSql(path string) ([]scannermodel.TblB, []scannermodel.TblS, error) {
	defer func() {
		err := s.removeDb(path)
		if err != nil {
			logging.GetLogger().Err(err).Msg("remove data db error")
		}
	}()
	dbPath := filepath.Join(path, "data.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		logging.GetLogger().Err(err).Msg("open hm sqllite error")
		return nil, nil, err
	}
	resB := []scannermodel.TblB{}
	err = db.Model(&scannermodel.TblB{}).Select("*").Find(&resB).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("get hm tbl_b error")
		return nil, nil, err
	}
	resS := []scannermodel.TblS{}
	err = db.Model(&scannermodel.TblS{}).Select("*").Find(&resS).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("get hm tbl_s error")
		return nil, nil, err
	}
	return resB, resS, nil
}

func (s *ScannerWebshell) removeDb(path string) error {
	dbPath := filepath.Join(path, "data.db")
	return os.Remove(dbPath)
}

func (s *ScannerWebshell) ScanDir(scanPath string) ([]scannermodel.TblB, []scannermodel.TblS, error) {
	str := consts.WebshellDir + fmt.Sprintf("%d", s.Token)
	err := s.cmdScan(str, scanPath)
	if err != nil {
		logging.GetLogger().Err(err).Msg("hm Scan error")
		return nil, nil, err
	}
	resB, resS, err := s.parseSql(str)
	if err != nil {
		logging.GetLogger().Err(err).Msg("parse data.db error")
		return nil, nil, err
	}
	return resB, resS, nil
}
