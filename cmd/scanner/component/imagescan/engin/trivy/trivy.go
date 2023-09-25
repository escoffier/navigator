package scanTrivy

import (
	"context"

	"github.com/go-redis/redis/v8"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy"
	trivylog "scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/log"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"
)

type TrivyEngin struct {
	Trivy        *trivy.Scanner
	CustomDBPath string // cnnvd,cnvd 的 bolt path
	TrivyDBPath  string // trivyDB 的 path

}

func (s *TrivyEngin) ScanVuln(ctx context.Context, imageName string) (*report.Report, error) {
	res, err := s.Trivy.Scan(ctx, imageName)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func NewTrivyEngin(client redis.Client) (*TrivyEngin, error) {
	_ = trivylog.InitLogger(false, false)

	vulnDBPath := "/root/alldb/trivy/trivy.db" // dockerFile中写死的，所以不使用常量

	trivyScanner, err := trivy.NewScannerWithRedis(client, vulnDBPath)
	if err != nil {
		return nil, err
	}

	// 只会在这里使用，所以不使用常量
	e := TrivyEngin{
		Trivy:        trivyScanner,
		CustomDBPath: "/root/alldb/trivy/custom.db", // dockerFile中写死的，所以不使用常量
		TrivyDBPath:  "/root/alldb/trivy/trivy.db",  // dockerFile中写死的，所以不使用常量
	}
	return &e, nil
}
