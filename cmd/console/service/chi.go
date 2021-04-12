package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/go-chi/jwtauth"
	"github.com/gorilla/securecookie"
	"github.com/jinzhu/gorm"
	"github.com/olivere/elastic/v7"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/console/api"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/alert"
	assetsSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/audit"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cleanup"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cluster"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cron"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/driftprevention"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/falco"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/microservice"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/rule"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scanner"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/seccomp"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"go.mongodb.org/mongo-driver/mongo"
)

func setupChiRouter(
	ctx context.Context,
	mongodb *mongo.Database,
	postgresDB *gorm.DB,
	es *elastic.Client,
	scapper *scapper.Scapper,
	scannerURL string,
	httpLoggerDisabled bool,
	cronService *cron.CronService,
	clusterService *cluster.ClusterService,
	redisClient *redis.Client,
	ruleService *rule.RuleService,
	alertService *alert.AlertService,
	driftPreventionService *driftprevention.DriftPreventionService,
	seccompProfileService *seccomp.SeccompProfileService,
	falcoService *falco.FalcoService,
	onlineVulnsSvc *assetsSvc.OnlineVulnsService,
	auditService *audit.AuditService,
	cleanupService *cleanup.CleanupService,
	scannerService *scanner.ScannerService,
	scapService *scapper.ScapService,
	harborClient *harbor.HarborRESTClient,
	microService *microservice.MicroService,
	emailOpts *flag.EmailOpts,
) http.Handler {
	ch := make(chan model.AccessLog, 1000)
	tokenAuth := jwtauth.New("HS256", securecookie.GenerateRandomKey(64), nil)
	r := chi.NewRouter()
	r.Use(jwtauth.Verifier(tokenAuth))
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Compress(5))
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(lang.AcceptLanguageMiddleware)
	r.Use(AccessMiddlewares(ch))
	if !httpLoggerDisabled {
		r.Use(middleware.Logger)
	}

	api.SetupRoutes(ctx, r, 24*time.Hour,
		tokenAuth,
		mongodb,
		postgresDB,
		scapper,
		scannerURL,
		cronService,
		clusterService,
		redisClient,
		ruleService,
		alertService,
		driftPreventionService,
		seccompProfileService,
		falcoService,
		onlineVulnsSvc,
		auditService,
		cleanupService,
		scannerService,
		scapService,
		harborClient,
		microService,
		emailOpts,
	)
	go logWorker(es, ch)

	return r
}

func logWorker(es *elastic.Client, ch chan model.AccessLog) {
	for {
		al := <-ch

		cstZone := time.FixedZone("CST", 8*3600)
		indexStr := "access_" + time.Now().In(cstZone).Format("2006-01-02")
		_, err := es.Index().
			Index(indexStr).
			BodyJson(al).
			Do(context.Background())
		if err != nil {
			logging.GetLogger().Info().Msgf("ES 写日志失败 write es error：%s", err)
		} else {
			logging.GetLogger().Info().Msgf("ES 写日志成功")
		}
	}
}

func AccessMiddlewares(ch chan model.AccessLog) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				al        model.AccessLog
				headerMap map[string][]string
			)

			headerData, _ := json.Marshal(r.Header)
			json.Unmarshal(headerData, &headerMap)
			delete(headerMap, "Authorization")
			body, _ := ioutil.ReadAll(r.Body)

			token, claims, err := jwtauth.FromContext(r.Context())
			if err == nil {
				if token == nil || !token.Valid {
				} else {
					username, _ := claims["user_name"].(string)
					al.Username = username
				}
			}

			al.Header = headerMap
			al.Body = string(body)
			al.Method = r.Method
			al.RemoteAddr = r.RemoteAddr
			al.Host = r.Host
			al.RequestURI = r.RequestURI
			al.Time = time.Now()
			ch <- al
			r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
			next.ServeHTTP(w, r)

		})
	}
}
