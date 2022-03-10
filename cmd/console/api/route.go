package api

import (
	"context"

	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-redis/redis/v8"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/pb"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/pkg/api/apikey"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

const (
	InternalAPIURLPrefix = "/api/openapi"
	OpenAPIURLPrefix     = "/openapi/v1"
	NormalAPIURLPrefix   = "/api/v2"
)

// SetupRoutes is to set up the chi router
func SetupRoutes(
	ctx context.Context,
	r *chi.Mux,
	tokenAuth *jwtauth.JWTAuth,
	rdb *databases.RDBInstance,
	scannerURL string,
	secProfileCoreURL string,
	microsegURL string,
	webhookURL string,
	redisClient *redis.Client,
	harborClient *harbor.HarborRESTClient,
	// imageService *image.ImageService,
	ecCli pb.EventsCenterBizServiceClient,
) {
	logging.Get().Debug().Msg("setting up routes...")

	api := newAPI(
		tokenAuth,
		rdb,
		scannerURL,
		secProfileCoreURL,
		microsegURL,
		webhookURL,
		redisClient,
		harborClient,
		ecCli,
	)
	r.Get("/ping", response.Pong)
	// disable swagger APIs
	// r.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL("swagger/doc.json")))

	// Open Api
	r.Route(InternalAPIURLPrefix, func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(apikey.ScannerValid())
			r.Route("/ATTCK", api.ATTCKOpen())
			r.Route("/scanner", api.scanner())
			r.Route("/assets", api.assets())
			r.Post("/hunter-report/{uuid}", api.reportKubeHunterResult())
		})
	})

	// Open API v1
	r.Route(OpenAPIURLPrefix, func(r chi.Router) {
		r.Route("/auth", api.openapiAuth())
		r.Group(func(r chi.Router) {
			r.Use(openAPIAccessCheck(api.rdb))
			r.Route("/platform", api.platformOpenapi()) // platform
			r.Route("/containerSec", api.OpenApiContainerSec())
			// proxy to tensor-microseg
			r.Handle("/microseg/*", api.microSegmentation())
		})
	})

	// api v2
	r.Route(NormalAPIURLPrefix, func(r chi.Router) {
		r.Route("/usercenter", api.userCenter())
		r.Group(func(r chi.Router) {
			// normal check
			r.Use(jwtauth.Verifier(api.tokenAuth), authenticator, jwtAccessCheck(api.rdb))

			r.Route("/platform", api.platform()) // platform
			r.Route("/containerSec", api.containerSec())

			// proxy to tensor-microseg
			r.Handle("/microseg/*", api.microSegmentation())
		})

	})
	r.Route("/internal", func(r chi.Router) {
		r.Route("/platform/assets", api.assets())
		r.Route("/platform/networkTopo", api.networkTopo())
		r.Route("/platform/apiscan", api.apiScan())
		r.Handle("/webhook/*", api.webhook())
		r.Route("/scap", api.scapInternal())
		r.Route("/defense", api.defense())
	})
}
