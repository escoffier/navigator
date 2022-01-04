package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-redis/redis/v8"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/pb"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/session"
	"gitlab.com/piccolo_su/vegeta/pkg/api/apikey"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
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
	postgresDB *rdbtools.GormWrapper,
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
		postgresDB,
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
			r.Route("/ATTCK", api.ATTCK())
			r.Route("/scanner", api.scanner())
			r.Route("/assets", api.assets())
			r.Post("/hunter-report/{uuid}", api.reportKubeHunterResult())
		})
	})

	// Open API v1
	r.Route(OpenAPIURLPrefix, func(r chi.Router) {
		r.Route("/auth", api.openapiAuth())
		r.Group(func(r chi.Router) {
			r.Use(openAPIAccessCheck(api.postgresDB))
			r.Route("/platform", api.platform()) // platform
			r.Route("/containerSec", api.containerSec())

			// proxy to tensor-microseg
			r.Handle("/microseg/*", api.microSegmentation())
		})
	})

	// api v2
	r.Route(NormalAPIURLPrefix, func(r chi.Router) {
		r.Route("/usercenter", api.userCenter())
		r.Group(func(r chi.Router) {
			// normal check
			r.Use(jwtauth.Verifier(api.tokenAuth))
			r.Use(jwtAccessCheck(api.postgresDB))

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
	})
}

const (
	accessCheckTimeout = time.Second * 3
)

func jwtAccessCheck(postgresDB *rdbtools.GormWrapper) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), accessCheckTimeout)
			defer cancel()

			token, claims, err := jwtauth.FromContext(ctx)
			if err != nil {
				RespAndLog(w, ctx,
					NewInvalidAuthToken(http.StatusUnauthorized,
						fmt.Errorf("error when getting token & claims from context: %w", err)))
				return
			}
			if token == nil || !token.Valid {
				RespAndLog(w, ctx,
					NewInvalidAuthToken(http.StatusUnauthorized,
						fmt.Errorf("token empty or invalid")))
				return
			}

			username, _ := claims[JWTKeyUsername].(string)
			sessionService, ok := session.GetService()
			if !ok {
				RespAndLog(w, ctx, ErrServiceNotReady)
				return
			}

			userSession, err := sessionService.GetUserSession(ctx, username)
			if err != nil {
				if err == session.ErrNotFound {
					RespAndLog(w, r.Context(),
						NewSessionExpired(http.StatusUnauthorized,
							fmt.Errorf("user not in cache")))
					return
				}

				RespAndLog(w, ctx, err)
				return
			}

			if err = sessionService.RefreshUserSession(ctx, username); err != nil {
				logging.Get().Err(err).Msgf("refresh session fail")
			}

			if userSession.Checked == false {
				RespAndLog(w, r.Context(),
					AccountUnActive(http.StatusForbidden,
						fmt.Errorf("account is not activated")))
				return
			}

			ctx = context.WithValue(r.Context(), util.CtxUserSessionKey, userSession)
			if r.Method == http.MethodGet {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			accessListUrl, err := dal.GetAccessUrl(postgresDB, userSession.ModuleID)
			if err != nil {
				RespAndLog(w, r.Context(), fmt.Errorf("select access error: %w", err))
				return
			}
			hasAccess := false

			currentURL := strings.ToLower(r.URL.Path)
			for i := range accessListUrl {
				url := strings.ToLower(accessListUrl[i])
				if strings.HasPrefix(currentURL, url) {
					hasAccess = true
					break
				}
			}

			if !hasAccess {
				RespAndLog(w, r.Context(),
					NewNoAccess(http.StatusForbidden,
						fmt.Errorf("access invalid")))
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
