package service

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth"
	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/console/api"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
)

var (
	jwtSignKey = []byte("skielsJKL@qlLKYY9091LSAqweVGY8769VHKskafhw239s$kskSJ)ksj!jHN7hJs")
)

func setupChiRouter(
	ctx context.Context,
	rdb *databases.RDBInstance,
	es *elastic.ESClient,
	scannerURL string,
	exportURL string,
	sherlockURL string,
	microsegURL string,
	webhookURL string,
	httpLoggerDisabled bool,
	httpAuditDisabled bool,
	redisClient *redis.Client,
	harborClient *harbor.HarborRESTClient,
	// ecCli pb.EventsCenterBizServiceClient,
) http.Handler {
	// ch := make(chan model.AccessLog, 1000)
	tokenAuth := jwtauth.New("HS256", jwtSignKey, nil)
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Compress(5))
	r.Use(Timeout(60 * time.Second))
	r.Use(lang.AcceptLanguageMiddleware)
	if !httpLoggerDisabled {
		r.Use(middleware.Logger)
	}

	api.SetupRoutes(ctx, r,
		tokenAuth,
		rdb,
		scannerURL,
		exportURL,
		sherlockURL,
		microsegURL,
		webhookURL,
		redisClient,
		harborClient,
		// ecCli,
		es,
		httpAuditDisabled,
	)

	return r
}

func Timeout(timeout time.Duration) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.RequestURI, "/files") {
				logging.GetLogger().Info().Str("RequestURI", r.RequestURI).Msg("Get download URI")
				timeout = 120 * time.Minute
			}

			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer func() {
				cancel()
				if ctx.Err() == context.DeadlineExceeded {
					w.WriteHeader(http.StatusGatewayTimeout)
				}
			}()

			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}
