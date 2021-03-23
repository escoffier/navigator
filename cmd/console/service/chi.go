package service

import (
	"context"
	"net/http"
	"time"

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
) http.Handler {
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

	api.SetupRoutes(ctx, r, 24*time.Hour,
		mongodb,
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
	)

	return r
}
