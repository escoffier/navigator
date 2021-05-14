package api

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/image"
	"gitlab.com/piccolo_su/vegeta/pkg/pb"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-redis/redis/v8"
	"github.com/patrickmn/go-cache"
	httpSwagger "github.com/swaggo/http-swagger"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/audit"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cleanup"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cluster"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cron"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/microservice"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/rule"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scanner"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type key int

const (
	userKey               key = iota
	UserSessionExpiration     = 30 * time.Minute
)

var (
	log *logging.Logger
)

func init() {
	log = logging.GetLogger()
}

// SetupRoutes is to set up the chi router
func SetupRoutes(
	ctx context.Context,
	r *chi.Mux,

	sessionExpiration time.Duration,
	tokenAuth *jwtauth.JWTAuth,
	mongodb *mongotools.DatabaseWrapper,
	postgresDB *rdbtools.GormWrapper,
	scapper *scapper.Scapper,
	scannerURL string,
	cronService *cron.CronService,
	clusterService *cluster.ClusterService,
	redisClient *redis.Client,
	ruleService *rule.RuleService,
	onlineVulnsSvc *assets.OnlineVulnsService,
	auditService *audit.AuditService,
	cleanupService *cleanup.Service,
	scannerService *scanner.ScannerService,
	scapService *scapper.ScapService,
	harborClient *harbor.HarborRESTClient,
	microService *microservice.MicroService,
	emailOpts *flag.EmailOpts,
	imageService *image.ImageService,
	ecCli pb.EventsCenterBizServiceClient,
) {
	log.Debug().Msg("setting up routes...")

	api := newAPI(ctx, sessionExpiration,
		tokenAuth,
		mongodb,
		postgresDB,
		scapper,
		scannerURL,
		cronService,
		clusterService,
		redisClient,
		ruleService,
		onlineVulnsSvc,
		auditService,
		cleanupService,
		scannerService,
		scapService,
		harborClient,
		microService,
		emailOpts,
		imageService,
		ecCli,
	)
	r.Get("/ping", response.Pong)
	r.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL("swagger/doc.json")))
	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/auth", api.restAuth())

		// needs authentication
		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(api.tokenAuth))
			r.Use(jwtAccessCheck(api.postgresDB, api.userCache))

			r.Route("/config", api.config())
			r.Route("/scanner", api.scanner())
			r.Route("/scap", api.scap())
			r.Route("/microservice", api.Microservice())
			r.Route("/onlineVulnerabilities", api.onlineVulnerabilities())
			r.Route("/riskExplorer", api.riskExplorer())
			r.Route("/runtimeDetectionConfig", api.runtimeDetectionConfig())
			r.Route("/audit", api.audit())
			r.Route("/cleanup", api.cleanup())
		})

		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(api.tokenAuth))
			r.Use(jwtAccessCheck(api.postgresDB, api.userCache))
			r.Route("/superAdmin", api.superAdmin())
		})

		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(api.tokenAuth))
			r.Use(jwtAllPass(api.userCache))
			r.Route("/user", api.user())
		})
	})

	//api v2

	r.Route("/api/v2", func(r chi.Router) {
		r.Route("/usercenter", api.userCenter())
		r.Group(func(r chi.Router) {
			//normal check
			r.Use(jwtauth.Verifier(api.tokenAuth))
			r.Use(jwtAccessCheck(api.postgresDB, api.userCache))

			r.Route("/platform", api.platform()) //platform
			r.Route("/containerSec", api.containerSec())

		})

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

			ctx := context.WithValue(r.Context(), userKey, userPtr)
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

			accessListUrl, err := model.GetAccessUrl(postgresDB, u.ModuleID)
			if err != nil {
				RespAndLog(w, r.Context(),
					NewMongoError(http.StatusInsufficientStorage,
						fmt.Errorf("select access error: %w", err)))
				return
			}
			hasAccess := false

			if r.Method != http.MethodGet {
				currentURL := strings.ToLower(r.URL.Path)
				for i := range accessListUrl {
					url := strings.ToLower(accessListUrl[i])
					if strings.HasPrefix(currentURL, url) {
						hasAccess = true
						break
					}
				}
			}

			if r.Method != "GET" && !hasAccess {
				RespAndLog(w, r.Context(),
					NewNoAccess(http.StatusForbidden,
						fmt.Errorf("access invalid")))
				return
			}

			ctx := context.WithValue(r.Context(), userKey, userPtr)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
