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
	"github.com/patrickmn/go-cache"
	httpSwagger "github.com/swaggo/http-swagger"
	"gitlab.com/piccolo_su/vegeta/pkg/api/apikey"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type key int

const (
	UserSessionExpiration = 10 * time.Minute
)

var (
	log *logging.Logger
)

func init() {
	log = logging.GetLogger()
}

const (
	OpenAPIURLPrefix   = "/openapi/v1"
	NormalAPIURLPrefix = "/api/v2"
)

// SetupRoutes is to set up the chi router
func SetupRoutes(
	ctx context.Context,
	r *chi.Mux,
	sessionExpiration time.Duration,
	tokenAuth *jwtauth.JWTAuth,
	mongodb *mongotools.DatabaseWrapper,
	postgresDB *rdbtools.GormWrapper,
	scannerURL string,
	microsegURL string,
	redisClient *redis.Client,
	harborClient *harbor.HarborRESTClient,
	emailOpts *flag.EmailOpts,
	// imageService *image.ImageService,
	ecCli pb.EventsCenterBizServiceClient,
) {
	log.Debug().Msg("setting up routes...")

	api := newAPI(ctx, sessionExpiration,
		tokenAuth,
		mongodb,
		postgresDB,
		scannerURL,
		microsegURL,
		redisClient,
		harborClient,
		emailOpts,
		ecCli,
	)
	r.Get("/ping", response.Pong)
	r.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL("swagger/doc.json")))

	// Open Api
	r.Route("/api/openapi", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(apikey.ScannerValid())
			r.Route("/ATTCK", api.ATTCK())
			r.Route("/scanner", api.scanner())
			r.Route("/assets", api.assets())
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
			r.Use(jwtAccessCheck(api.postgresDB, api.userCache))

			r.Route("/platform", api.platform()) // platform
			r.Route("/containerSec", api.containerSec())

			// proxy to tensor-microseg
			r.Handle("/microseg/*", api.microSegmentation())
		})

	})
	r.Route("/internal", func(r chi.Router) {
		r.Route("/platform/assets", api.assets())
		r.Route("/platform/networkTopo", api.networkTopo())
	})
}

func jwtAllPass(userCache *cache.Cache) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, claims, err := jwtauth.FromContext(r.Context())

			if err != nil {
				RespAndLog(w, r.Context(),
					NewInvalidAuthToken(http.StatusUnauthorized,
						fmt.Errorf("Error when getting token & claims from context: %w", err)))
				return
			}
			if token == nil || !token.Valid {
				RespAndLog(w, r.Context(),
					NewInvalidAuthToken(http.StatusUnauthorized,
						fmt.Errorf("Token empty or invalid")))
				return
			}
			username, _ := claims[JWT_KEY_USERNAME].(string)
			userPtr, ok := userCache.Get(username)
			if !ok {
				testWithLogJson("jwt-jwtAccessCheck()", "user get error")
				RespAndLog(w, r.Context(),
					NewSessionExpired(http.StatusUnauthorized,
						fmt.Errorf("User not in cache")))
				return
			}

			u, _ := userPtr.(*model.User)
			userCache.Set(username, u, cache.DefaultExpiration)

			ctx := context.WithValue(r.Context(), util.CtxUserKey, u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func jwtAccessCheck(postgresDB *rdbtools.GormWrapper, userCache *cache.Cache) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, claims, err := jwtauth.FromContext(r.Context())

			if err != nil {
				RespAndLog(w, r.Context(),
					NewInvalidAuthToken(http.StatusUnauthorized,
						fmt.Errorf("Error when getting token & claims from context: %w", err)))
				return
			}
			if token == nil || !token.Valid {
				RespAndLog(w, r.Context(),
					NewInvalidAuthToken(http.StatusUnauthorized,
						fmt.Errorf("Token empty or invalid")))
				return
			}

			username, _ := claims[JWT_KEY_USERNAME].(string)
			userPtr, ok := userCache.Get(username)
			if !ok {
				testWithLogJson("jwt-jwtAccessCheck()", "user get error")
				RespAndLog(w, r.Context(),
					NewSessionExpired(http.StatusUnauthorized,
						fmt.Errorf("User not in cache")))
				return
			}

			u, _ := userPtr.(*model.User)
			userCache.Set(username, u, UserSessionExpiration)

			if u.Checked == false {
				RespAndLog(w, r.Context(),
					AccountUnActive(http.StatusForbidden,
						fmt.Errorf("account is not activated")))
				return
			}

			ctx := context.WithValue(r.Context(), util.CtxUserKey, u)
			if r.Method == http.MethodGet {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			accessListUrl, err := dal.GetAccessUrl(postgresDB, u.ModuleID)
			if err != nil {
				RespAndLog(w, r.Context(),
					NewMongoError(http.StatusInsufficientStorage,
						fmt.Errorf("select access error: %w", err)))
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
