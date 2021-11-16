package component

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/go-redis/redis/v8"
	vulnupdata "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy"
	trivylog "scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/log"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"
)

var (
	TrivyService *TrivyServer
	once         sync.Once
)

type TrivyServer struct {
	trivy  *trivy.Scanner
	update *vulnupdata.UpdataService
}

func NewTrivyServer(redis redis.Client, vulnpath string) (*TrivyServer, error) {
	once.Do(func() {
		_ = trivylog.InitLogger(false, true)
		ch := make(chan string)
		u := vulnupdata.NewUpdataService(vulnpath, ch)
		u.InitUpdateSvc()
		t, err := trivy.NewScannerWithRedis(redis, filepath.Join(vulnpath, "init_db"))
		if err != nil {
			panic(fmt.Sprintf("init db scannert failed, err: %v\n", err))
		}
		TrivyService = &TrivyServer{
			trivy:  t,
			update: u,
		}
	})

	return TrivyService, nil
}
func (t *TrivyServer) Scan(ctx context.Context, image string) (*report.Report, error) {
	return t.trivy.Scan(ctx, image)
}

func (t *TrivyServer) Run(ctx context.Context) error {
	go t.update.Run(false, t.update.VolumePath, t.update.Ch)
	go func() {
		for path := range t.update.Ch {
			logging.GetLogger().Info().Msgf("get ch Path :%v", path)
			if path == "err" {
				continue
			}
			if err := t.trivy.SetBoltDB(path); err != nil {
				logging.GetLogger().Err(err).Msg("update scannert db error")
				continue
			}
			logging.GetLogger().Info().Msg("scannert updata DB success")
		}
	}()

	return nil
}
