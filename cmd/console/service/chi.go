package service

import (
	"context"
	"net/http"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth"
	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/console/api"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
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
		es,
		httpAuditDisabled,
	)

	return r
}

func checkChangeTimeout(URI string) bool {
	checkList := []string{"/files", "ci/tidb/assets", "vulns/updata"}
	for k := range checkList {
		if strings.Contains(URI, checkList[k]) {
			return true
		}
	}
	return false
}

func Timeout(timeout time.Duration) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			if checkChangeTimeout(r.RequestURI) {
				timeout = 120 * time.Minute
				logging.GetLogger().Info().Str("requestURI", r.RequestURI).Dur("timeout", timeout).Msg("change api timeout")
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
