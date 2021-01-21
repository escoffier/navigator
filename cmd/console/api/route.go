package api

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/microservice"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-redis/redis/v8"
	"github.com/patrickmn/go-cache"
	httpSwagger "github.com/swaggo/http-swagger"
	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/alert"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/audit"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cleanup"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cluster"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cron"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/onlinevulns"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/rule"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scanner"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type key int

const (
	userKey key = iota
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
	mongodb *mongo.Database,
	scapper *scapper.Scapper,
	scannerURL string,
	cronService *cron.CronService,
	clusterService *cluster.ClusterService,
	redisClient *redis.Client,
	ruleService *rule.RuleService,
	alertService *alert.AlertService,
	onlineVulnsSvc *onlinevulns.OnlineVulnsService,
	auditService *audit.AuditService,
	cleanupService *cleanup.CleanupService,
	scannerService *scanner.ScannerService,
	scapService *scapper.ScapService,
	harborClient *harbor.HarborRESTClient,
	microService *microservice.MicroService,
) {
	log.Debug().Msg("setting up routes...")

	api := newAPI(ctx, sessionExpiration,
		mongodb,
		scapper,
		scannerURL,
		cronService,
		clusterService,
		redisClient,
		ruleService,
		alertService,
		onlineVulnsSvc,
		auditService,
		cleanupService,
		scannerService,
		scapService,
		harborClient,
		microService,
	)
	r.Get("/ping", response.Pong)
	r.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL("swagger/doc.json")))
	r.Route("/harbor/api/v1", api.harbor())
	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/auth", api.restAuth())

		// needs authentication
		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(api.tokenAuth))

			// custom authenticator
			r.Use(jwtAccessCheck(api.mongodb, api.userCache))

			r.Route("/config", api.config())
			r.Route("/scanner", api.scanner())
			r.Route("/scap", api.scap())
			r.Route("/microservice", api.Microservice())
			r.Route("/onlineVulnerabilities", api.onlineVulnerabilities())
			r.Route("/runtimeDetectionConfig", api.runtimeDetectionConfig())
			r.Route("/alerts", api.alert())
			r.Route("/audit", api.audit())
			r.Route("/cleanup", api.cleanup())
		})

		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(api.tokenAuth))
			r.Use(jwtAccessCheck(api.mongodb, api.userCache))
			r.Route("/superAdmin", api.superAdmin())
		})

		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(api.tokenAuth))
			r.Use(jwtAllPass(api.userCache))
			r.Route("/user", api.user())
		})
	})
}

func jwtAuthenticator(userCache *cache.Cache) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, claims, err := jwtauth.FromContext(r.Context())

			ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
			defer cancel()

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

			// check if we can find the user's session
			username := claims["username"].(string)
			userPtr, ok := userCache.Get(username)
			if !ok {
				RespAndLog(w, r.Context(),
					NewSessionExpired(http.StatusUnauthorized,
						fmt.Errorf("User not in cache")))
				return
			}

			// reset the TTL for the user if found
			userCache.Set(
				username,
				userPtr,
				cache.DefaultExpiration)

			ctx = context.WithValue(r.Context(), userKey, userPtr)

			// Token is authenticated, pass it through
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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

func jwtAccessCheck(mongodb *mongo.Database, userCache *cache.Cache) func(http.Handler) http.Handler {
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

			if username == "admin" {
				ctx := context.WithValue(r.Context(), userKey, userPtr)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			u, _ := userPtr.(*model.User)
			userCache.Set(username, u, cache.DefaultExpiration)

			c, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()

			_, roleNames, err := model.SelectRelaUserRole(c, mongodb, username, "")
			if err != nil {
				RespAndLog(w, r.Context(),
					NewMongoError(http.StatusInsufficientStorage,
						fmt.Errorf("select User error: %w", err)))
				return
			}

			accessNameList := make([]string, 0, 100)
			for _, e := range roleNames {
				_, accessNames, err := model.SelectRelaRoleAccess(c, mongodb, e, "")
				if err != nil {
					RespAndLog(w, r.Context(),
						NewMongoError(http.StatusInsufficientStorage,
							fmt.Errorf("select Role Access relation error: %w", err)))
					return
				}
				accessNameList = append(accessNameList, accessNames...)
			}

			accessList, err := model.SelectAccessMulti(c, mongodb, accessNameList)
			if err != nil {
				RespAndLog(w, r.Context(),
					NewMongoError(http.StatusInsufficientStorage,
						fmt.Errorf("select access error: %w", err)))
				return
			}

			hasAccess := false
			currentURL := strings.ToLower(r.URL.Path)
			for i := range accessList {
				url := strings.ToLower(accessList[i].URL)
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

			ctx := context.WithValue(r.Context(), userKey, userPtr)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
