package api

import (
	"context"

	"github.com/go-chi/chi"
	"github.com/go-redis/redis/v8"

	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/translate"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/api/apikey"
	"gitlab.com/piccolo_su/vegeta/pkg/audit"
	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/middleware"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/token"
)

const (
	InternalAPIURLPrefix = "/api/openapi"
	OpenAPIURLPrefix     = "/openapi/v1"
	NormalAPIURLPrefix   = "/api/v2"
	WebsocketURLPrefix   = "/ws/v1"
)

// SetupRoutes is to set up the chi router
func SetupRoutes(
	ctx context.Context,
	r *chi.Mux,
	tokenManager token.Manager,
	rdb *databases.RDBInstance,
	scannerURL string,
	exportURL string,
	sherlockURL string,
	microsegURL string,
	webhookURL string,
	sherlockClient *echelper.SherlockClient,
	redisClient *redis.Client,
	harborClient *harbor.HarborRESTClient,
	es *elastic.ESClient,
	translation *translate.Translation,
	httpAuditDisabled bool,
	clusterManager *k8s.ClusterManager,
	resSvc *assets.TensorResourcesService,
) {
	logging.Get().Debug().Msg("setting up routes...")

	api := newAPI(
		tokenManager,
		rdb,
		scannerURL,
		exportURL,
		sherlockURL,
		microsegURL,
		webhookURL,
		sherlockClient,
		redisClient,
		harborClient,
		es,
		translation,
		httpAuditDisabled,
		clusterManager,
		resSvc,
	)
	r.Get("/ping", response.Pong)
	// disable swagger APIs
	// r.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL("swagger/doc.json")))

	r.NotFound(api.NotFound)
	// Internal Api
	r.Route(InternalAPIURLPrefix, func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(apikey.ScannerValid())
			r.Route("/ATTCK", api.ATTCKOpen())
			r.Route("/scanner", api.scanner())
			r.Route("/export", api.export())
			r.Route("/assets", api.assets())
			r.Route("/drift", api.drift())
			r.Route("/waf", api.waf())
			r.Post("/hunter-report/{uuid}", api.reportKubeHunterResult())
			r.Route("/memshell", api.memshell())
			// r.Route("/behavioral-learn", api.behavioralLearn())
		})
	})

	// Open API v1
	r.Route(OpenAPIURLPrefix, func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.LicenseVerify)
			r.Route("/auth", api.openapiAuth())
		})
		r.Group(func(r chi.Router) {
			r.Use(openAPIAccessCheck(api.rdb))
			r.Route("/platform", api.platformOpenapi()) // platform
			r.Route("/containerSec", api.OpenApiContainerSec())
			// proxy to tensor-microseg
			r.Handle("/microseg/*", api.microSegmentation())
		})
	})

	// ws v1
	r.Route(WebsocketURLPrefix, func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.Authenticator(api.tokenManager, api.rdb), middleware.Access(api.rdb))
			r.Get("/biz", api.wsHandler()) // 业务长连接
		})
	})

	// api v2
	r.Route(NormalAPIURLPrefix, func(r chi.Router) {
		r.Route("/usercenter", api.userCenter())
		r.Route("/license", api.licenseRouter())

		r.Group(func(r chi.Router) {
			r.Use(downloadAuth())
			r.Route("/files", api.exportDownload())
		})
		// r.Handle("/microseg/*", api.microSegmentation())

		r.Group(func(r chi.Router) {
			// normal check
			r.Use(middleware.Authenticator(api.tokenManager, api.rdb), middleware.Access(api.rdb))
			if !httpAuditDisabled {
				cli, err := es.Get()
				if err == nil {
					r.Use(audit.ESAudit(cli))
				}
			}

			r.Route("/platform", api.platform()) // platform
			r.Route("/containerSec", api.containerSec())

			// proxy to tensor-microseg
			r.Route("/microseg", api.microseg)
			// r.Handle("/microseg/*", api.microSegmentation())
		})
	})

	r.Route("/internal", func(r chi.Router) {
		r.Route("/platform/assets", api.assets())
		r.Route("/platform/networkTopo", api.networkTopo())
		r.Route("/platform/apiscan", api.apiScan())
		r.Handle("/webhook/*", api.webhook())
		r.Route("/scap", api.scapInternal())
		r.Route("/defense", api.defense())
		r.Route("/platform/waf", api.waf())
		r.Route("/waf", api.waf())
		r.Handle("/microseg/*", api.microSegmentation())
		r.Get("/biz", api.wsHandler())
	})
}
