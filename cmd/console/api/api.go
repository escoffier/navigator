package api

import (
	"context"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/alert"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cluster"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cron"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/onlinevulns"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/rule"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"

	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-redis/redis/v8"
	"github.com/gorilla/securecookie"
	version "github.com/mcuadros/go-version"
	param "github.com/oceanicdev/chi-param"
	"github.com/patrickmn/go-cache"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type api struct {
	ctx            context.Context
	userCache      *cache.Cache
	tokenAuth      *jwtauth.JWTAuth
	mongodb        *mongo.Database
	scapper        *scapper.Scapper
	syncData       *util.ImageVulnerabilityCache
	scannerURL     string
	cronService    *cron.CronService
	clusterService *cluster.ClusterService
	redisClient    *redis.Client
	ruleService    *rule.RuleService
	alertService   *alert.AlertService
	onlineVulnsSvc *onlinevulns.OnlineVulnsService

	// For Harbor API
	scanResultLocalBackoffCache    map[string]int // maps scantask ID to last backoff in secs
	scanResultLocalBackoffCacheMux sync.Mutex
	unprocessableEntityCache       *cache.Cache
}

func newAPI(
	ctx context.Context,
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
) *api {
	return &api{
		ctx:                         ctx,
		userCache:                   cache.New(sessionExpiration, time.Minute),
		tokenAuth:                   jwtauth.New("HS256", securecookie.GenerateRandomKey(64), nil),
		mongodb:                     mongodb,
		scapper:                     scapper,
		syncData:                    util.NewImageVulnerabilityCache(mongodb, redisClient, ctx),
		scannerURL:                  scannerURL,
		cronService:                 cronService,
		clusterService:              clusterService,
		redisClient:                 redisClient,
		ruleService:                 ruleService,
		alertService:                alertService,
		onlineVulnsSvc:              onlineVulnsSvc,
		scanResultLocalBackoffCache: make(map[string]int),
		unprocessableEntityCache:    cache.New(5*60*time.Second, 60*time.Second),
	}
}

func (api *api) getTimeoutCtx(timeout ...time.Duration) (context.Context, context.CancelFunc) {
	if timeout == nil {
		return context.WithTimeout(api.ctx, 10*time.Second)
	}
	return context.WithTimeout(api.ctx, timeout[0])
}

func (api *api) getOffsetAndLimit(r *http.Request) (int64, int64) {
	offset, err := param.QueryUint(r, "offset")
	if err != nil {
		offset = 0
	}
	limit, err := param.QueryUint(r, "limit")
	if err != nil {
		limit = 500
	}
	if limit > 10000 {
		limit = 10000
	}
	return int64(offset), int64(limit)
}

func (api *api) sortBy(first interface{}, second interface{}, sortBy string, sortOrder string) bool {
	d1 := reflect.ValueOf(first).Elem()
	d2 := reflect.ValueOf(second).Elem()
	for i := 0; i < d1.NumField(); i++ {
		typeField := d1.Type().Field(i).Name
		if typeField == strings.Title(sortBy) {
			val1 := d1.Field(i)
			val2 := d2.Field(i)
			switch val1.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				if sortOrder == "asc" {
					return val1.Int() < val2.Int()
				}
				return val1.Int() > val2.Int()
			case reflect.String:
				matched, err := regexp.MatchString(`^\d+\.\d+\.\d+$`, val1.String())
				// Do we want to handle it or just do other sorting then?
				if err != nil {
					logging.GetLogger().Warn().
						Str("val1", val1.String()).
						Msg("Error regex matching in sorting")
					matched = false
				}
				if matched {
					if sortOrder == "asc" {
						return version.CompareSimple(val1.String(), val2.String()) < 0
					}
					return version.CompareSimple(val2.String(), val1.String()) > 0
				}
				if sortOrder == "asc" {
					return val1.String() < val2.String()
				}
				return val1.String() > val2.String()
			}
		}
	}
	if sortOrder == "asc" {
		return fmt.Sprintf("%v", first) < fmt.Sprintf("%v", second)
	}
	return fmt.Sprintf("%v", first) > fmt.Sprintf("%v", second)
}

func getClusterIDFromURL(r *http.Request) (primitive.ObjectID, error) {
	clusterID := chi.URLParam(r, "clusterID")
	if clusterID == "" {
		return primitive.NilObjectID, errors.New("clusterID is not provided")
	}
	return primitive.ObjectIDFromHex(clusterID)
}
