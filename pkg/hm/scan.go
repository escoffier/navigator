package hm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

const (
	hmBinaryFile = "/usr/bin/hm"
	resultFile   = "result.csv"
	dataDBFile   = "data.db"
)

type HMWebshell struct {
	cmdDir   string
	hmBinary string
}

type ResultItem struct {
	Name       string
	Suggestion string
	Path       string
}

type Option func(hmw *HMWebshell)

func NewHMWebshell(opts ...Option) *HMWebshell {
	return &HMWebshell{
		cmdDir: "/tmp",
	}
}

func (hmw *HMWebshell) GenerateCmdDir(path string) error {
	sum := sha256.Sum256([]byte(path))
	hmw.cmdDir = "/tmp/" + hex.EncodeToString(sum[:])
	logging.GetLogger().Debug().Str("cmdDir", hmw.cmdDir).Msg("generate cmd dir")

	err := os.Mkdir(hmw.cmdDir, 0777)
	if err != nil {
		logging.GetLogger().Err(err).Msg("create cmd dir failed")
		return err
	}

	// copy hm binary
	hmBinaryPath := filepath.Join(hmw.cmdDir, "hm")
	hmw.hmBinary = hmBinaryPath
	src, err := os.Open(hmBinaryFile)
	if err != nil {
		logging.GetLogger().Err(err).Msg("open hm binary failed")
		return err
	}
	defer src.Close()

	dst, err := os.Create(hmw.hmBinary)
	if err != nil {
		logging.GetLogger().Err(err).Msg("create hm binary failed")
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	if err != nil {
		logging.GetLogger().Err(err).Msg("copy hm binary failed")
		return err
	}

	srcInfo, err := os.Stat(hmBinaryFile)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get hm binary info failed")
		return err
	}
	err = os.Chmod(hmw.hmBinary, srcInfo.Mode())
	if err != nil {
		logging.GetLogger().Err(err).Msg("chmod hm binary failed")
		return err
	}

	return nil
}

func (hmw *HMWebshell) ScanFile(path string) {
	cmd := exec.Command(hmw.hmBinary, "scan", path)
	cmd.Dir = hmw.cmdDir
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err := cmd.Run()
	if err != nil {
		logging.GetLogger().Err(err).Str("stdout", outb.String()).Str("stderr", errb.String()).Msg("scan file failed")
		return
	}
}

func (hmw *HMWebshell) readFromDB() ([]ResultItem, error) {
	// data.db:
	// 1,Godzilla ASPX-ASPX后门，建议清理,../test_webshell/123.aspx
	// 2,Godzilla JSP-JSP后门，建议清理,../test_webshell/123.jsp

	dataDBPath := filepath.Join(hmw.cmdDir, dataDBFile)
	_, err := os.Stat(dataDBPath)
	if err != nil {
		logging.GetLogger().Err(err).Msg("data.db not exist")
		return nil, err
	}

	db, err := gorm.Open(sqlite.Open(dataDBPath), &gorm.Config{})
	if err != nil {
		logging.GetLogger().Err(err).Msg("open hm sqlite error")
		return nil, err
	}
	resB := make([]imagesecModel.CertainWebshell, 0)

	err = db.Model(&imagesecModel.CertainWebshell{}).Select("*").Find(&resB).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("get hm tbl_b error")
		return nil, err
	}
	resS := make([]imagesecModel.MaybeWebshell, 0)

	err = db.Model(&imagesecModel.MaybeWebshell{}).Select("*").Find(&resS).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("get hm tbl_s error")
		return nil, err
	}
	resultItems := make([]ResultItem, 0)
	for _, item := range resB {
		resultItem := ResultItem{
			Name: item.Description,
			Path: item.Filepath,
		}
		resultItems = append(resultItems, resultItem)
	}
	for _, item := range resS {
		resultItem := ResultItem{
			Name: item.Description,
			Path: item.Filepath,
		}
		resultItems = append(resultItems, resultItem)
	}

	return resultItems, nil
}

func (hmw *HMWebshell) ReadAndCleanResult() ([]ResultItem, error) {
	// result.csv:
	// 序号,类型,路径
	// 1,Godzilla ASPX-ASPX后门，建议清理,../test_webshell/123.aspx
	// 2,Godzilla JSP-JSP后门，建议清理,../test_webshell/123.jsp

	defer func() {
		//delete cmd dir
		err := os.RemoveAll(hmw.cmdDir)
		if err != nil {
			logging.GetLogger().Err(err).Str("cmd dir", hmw.cmdDir).Msg("remove cmd dir failed")
		}
	}()

	return hmw.readFromDB()
}
