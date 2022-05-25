package service

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth"
	redis "github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/console/api"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/pb"
)

var (
	jwtSignKey = []byte("skielsJKL@qlLKYY9091LSAqweVGY8769VHKskafhw239s$kskSJ)ksj!jHN7hJs")
)

func setupChiRouter(
	ctx context.Context,
	rdb *databases.RDBInstance,
	es *elastic.ESClient,
	scannerURL string,
	secProfilesCoreURL string,
	microsegURL string,
	webhookURL string,
	httpLoggerDisabled bool,
	redisClient *redis.Client,
	harborClient *harbor.HarborRESTClient,
	ecCli pb.EventsCenterBizServiceClient,
) http.Handler {
	// ch := make(chan model.AccessLog, 1000)
	tokenAuth := jwtauth.New("HS256", jwtSignKey, nil)
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Compress(5))
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(lang.AcceptLanguageMiddleware)
	if !httpLoggerDisabled {
		r.Use(middleware.Logger)
	}
	//r.Use(audit.Audit)

	api.SetupRoutes(ctx, r,
		tokenAuth,
		rdb,
		scannerURL,
		secProfilesCoreURL,
		microsegURL,
		webhookURL,
		redisClient,
		harborClient,
		ecCli,
		es,
	)

	return r
}
