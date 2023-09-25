package aviraengin

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

func TestNewClamavSrv(t *testing.T) {
	srv, err := NewSavServer()
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("NewClamavSrv")
		return
	}

	data, err := os.ReadFile("/root/work/work存档/avira.zip")
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("ReadFile")
		return
	}

	if _, err := srv.UpdateDB(context.Background(), imagesecModel.UpdateDbParam{
		Updater: "liuqianli",
		DbType:  consts.AviraName,
		Data:    data,
	}); err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("ReadFile")
		return
	}
	for i := 0; i < 5; i++ {
		file2, err := srv.ScanFile(context.Background(), "/root/app/kafka_2.13-3.5.0/bin/windows/kafka-metadata-quorum.bat")
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msg("ScanFile")
			return
		}
		fmt.Println(file2)
		time.Sleep(10 * time.Second)
	}

}
